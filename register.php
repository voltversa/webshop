<?php
/* ================== App bootstrap ================== */
$APP_ENV = isset($_ENV['APP_ENV']) ? $_ENV['APP_ENV'] : 'prod'; // 'dev' or 'prod'
$APP_LOG = __DIR__ . '/../_logs/app.log';                       // ideally outside webroot

// Ensure log directory exists
$__logDir = dirname($APP_LOG);
if (!is_dir($__logDir)) { @mkdir($__logDir, 0750, true); }

/* ---------- Error & Exception Handling (top-level) ---------- */
ini_set('display_errors', $APP_ENV === 'dev' ? '1' : '0');
ini_set('log_errors', '1');

if (!function_exists('app_log')) {
    function app_log($level, $message, $ctx = []) {
        global $APP_LOG;
        $entry = [
            'ts'     => date('c'),
            'level'  => $level,
            'ip'     => isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : null,
            'method' => isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : null,
            'uri'    => isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : null,
            'msg'    => $message,
            'ctx'    => $ctx,
        ];
        error_log(json_encode($entry, JSON_UNESCAPED_SLASHES) . PHP_EOL, 3, $APP_LOG);
    }
}

set_error_handler(function ($severity, $message, $file, $line) {
    if (!(error_reporting() & $severity)) { return false; } // respect @
    app_log('php_error', $message, ['file'=>$file,'line'=>$line,'severity'=>$severity]);
    throw new ErrorException($message, 0, $severity, $file, $line);
});
set_exception_handler(function ($e) {
    app_log('exception', $e->getMessage(), [
        'file'  => $e->getFile(),
        'line'  => $e->getLine(),
        'trace' => array_slice(explode("\n", $e->getTraceAsString()), 0, 20),
    ]);
    http_response_code(500);
    if (!headers_sent()) { header('Content-Type: text/html; charset=utf-8'); }
    echo '<h1>Something went wrong</h1><p>Please try again later.</p>';
    exit;
});
register_shutdown_function(function () {
    $e = error_get_last();
    if ($e && in_array($e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
        app_log('fatal', $e['message'], ['file'=>$e['file'], 'line'=>$e['line']]);
        http_response_code(500);
        if (!headers_sent()) { header('Content-Type: text/html; charset=utf-8'); }
        echo '<h1>Unexpected error</h1><p>Please try again later.</p>';
    }
});

/* ---------- Session cookie hardening (before session_start) ---------- */
$__secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
session_set_cookie_params([
    'httponly' => true,
    'secure'   => $__secure,
    'samesite' => 'Lax',
]);
session_start();

/* ---------- Security headers ---------- */
header('Content-Type: text/html; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
header('Cross-Origin-Opener-Policy: same-origin');
// header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; font-src 'self'; frame-ancestors 'self';");

/* ---------- CSRF token for forms ---------- */
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf = $_SESSION['csrf_token'];

/* ================== DB connection (from config.php) ================== */
require 'config.php'; // must provide $conn (MySQLi)

/* ================== Registration logic ================== */
$errors = [];
$success = false;

// Make mysqli throw exceptions so try/catch works
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    // CSRF check
    $token = isset($_POST['csrf_token']) ? $_POST['csrf_token'] : '';
    if (!hash_equals($_SESSION['csrf_token'], $token)) {
        app_log('csrf', 'CSRF token mismatch on register');
        http_response_code(400);
        $errors[] = 'Invalid request.';
    } else {
        // Collect + normalize inputs
        $first_name = isset($_POST['first_name']) ? trim($_POST['first_name']) : '';
        $last_name  = isset($_POST['last_name'])  ? trim($_POST['last_name'])  : '';
        $email      = isset($_POST['email'])      ? strtolower(trim($_POST['email'])) : '';
        $password   = isset($_POST['password'])   ? $_POST['password']         : '';
        $contact    = isset($_POST['contact'])    ? trim($_POST['contact'])     : '';
        $address    = isset($_POST['address'])    ? trim($_POST['address'])     : '';

        // Validation
        if ($first_name === '' || $last_name === '') {
            $errors[] = "First name and last name are required.";
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = "Invalid email format.";
        }
        if (strlen($password) < 6) {
            $errors[] = "Password must be at least 6 characters.";
        }
        // Optional: max lengths (avoid DB truncation)
        if (strlen($first_name) > 100 || strlen($last_name) > 100) {
            $errors[] = "Names must be at most 100 characters.";
        }
        if (strlen($email) > 190) {
            $errors[] = "Email is too long.";
        }

        if (empty($errors)) {
            try {
                // Check if email already exists (active or not)
                $stmt = $conn->prepare("SELECT 1 FROM users WHERE email = ? LIMIT 1");
                $stmt->bind_param("s", $email);
                $stmt->execute();
                $result = $stmt->get_result();
                $exists = $result && $result->fetch_row();
                if ($result) { $result->free(); }
                $stmt->close();

                if ($exists) {
                    $errors[] = "Email already registered.";
                } else {
                    // Insert user
                    $hashed = password_hash($password, PASSWORD_DEFAULT);
                    $stmt = $conn->prepare("
                        INSERT INTO users
                            (email, password, first_name, last_name, contact, address, role, active)
                        VALUES
                            (?, ?, ?, ?, ?, ?, 'normal', 1)
                    ");
                    $stmt->bind_param("ssssss", $email, $hashed, $first_name, $last_name, $contact, $address);
                    $stmt->execute();
                    $stmt->close();
                    $success = true;
                }
            } catch (mysqli_sql_exception $e) {
                // If you have a UNIQUE index on email, catch duplicate-key errors gracefully
                $msg = $e->getMessage();
                app_log('db_register_error', 'Registration insert failed', ['error' => $msg, 'email' => $email]);
                // MySQL duplicate entry error code is 1062
                if (strpos($msg, '1062') !== false) {
                    $errors[] = "Email already registered.";
                } else {
                    $errors[] = "Registration temporarily unavailable. Please try again later.";
                }
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Register — My Webshop</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link rel="stylesheet" href="index.css">
  <link rel="stylesheet" href="login.css">
  <link rel="stylesheet" href="fontawesome-free-7.0.0-web/css/all.min.css">
  <script src="search.js" defer></script>
<style>
  /* ===== REGISTER FORM STYLING ===== */
  .login-container {
    max-width: 500px;
    margin: 50px auto;
    background-color: var(--header-bg);
    padding: 30px 40px;
    border-radius: 8px;
    box-shadow: 0 2px 8px var(--shadow);
    color: var(--text-color);
  }
  .login-container h2 { margin-bottom: 20px; text-align: center; color: var(--text-color); }
  .login-container form { display: flex; flex-direction: column; }
  .login-container label { margin-bottom: 5px; font-weight: bold; color: var(--text-color); }
  .login-container input[type="text"],
  .login-container input[type="email"],
  .login-container input[type="password"] {
    padding: 10px; margin-bottom: 20px; border: 1px solid #ccc; border-radius: 4px;
    background-color: var(--bg-color); color: var(--text-color);
  }
  .login-container input[type="submit"] {
    background-color: var(--button-bg); color: white; padding: 10px; border: none; border-radius: 4px;
    font-weight: bold; cursor: pointer; transition: background-color 0.3s ease;
  }
  .login-container input[type="submit"]:hover { background-color: var(--button-hover); }
  .login-container p { text-align: center; margin-top: 10px; }
  body.dark .login-container { background-color: var(--nav-bg); box-shadow: 0 2px 8px var(--shadow); }
  body.dark .login-container input { background-color: #1e1e1e; border: 1px solid #444; color: white; }
</style>
</head>
<body>

<!-- HEADER -->
<header>
  <a href="index.php"><img src="images/logo.png" id="logo" alt="Logo"></a>

  <!-- Search Bar (same AJAX as index/category) -->
  <div class="search-container">
    <form class="search-bar" onsubmit="start(); return false;">
      <select name="catg" id="catg" aria-label="Category">
        <option value="">All Categories</option>
        <option value="Clothing">Clothing</option>
        <option value="Electronics">Electronics</option>
        <option value="Gifts">Gifts</option>
        <option value="Pets">Pets</option>
      </select>
      <input type="text" id="searchinput" placeholder="Search..." aria-label="Search">
      <button type="submit" title="Search" aria-label="Search"><i class="fas fa-search"></i></button>
    </form>
  </div>

  <div class="user-links">
    <a id="darkModeToggle" title="Toggle dark mode">🌙 Mood</a>
    <a href="#" title="Cart"><i class="fas fa-shopping-basket"></i> Cart</a>
  </div>
</header>

<!-- CATEGORY NAVIGATION -->
<nav>
  <ul class="category-links">
    <li><a href="category.php?category=Clothing">Clothing</a></li>
    <li><a href="category.php?category=Electronics">Electronics</a></li>
    <li><a href="category.php?category=Pets">Pets</a></li>
    <li><a href="category.php?category=Gifts">Gifts</a></li>
    <li><a href="category.php?category=Best%20Sellers">Best Sellers</a></li>
  </ul>
</nav>

<div class="login-container">
  <h2>Create an Account</h2>

  <?php
    foreach ($errors as $e) {
        echo '<p style="color:red;">' . htmlspecialchars($e, ENT_QUOTES, 'UTF-8') . '</p>';
    }
    if ($success) {
        echo "<p style='color:green;'>Registration successful! <a href='login.php'>Login here</a>.</p>";
    }
  ?>

  <form method="post" novalidate>
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">

    <label for="first_name">First Name *</label>
    <input type="text" name="first_name" id="first_name" required maxlength="100" value="<?= isset($_POST['first_name']) ? htmlspecialchars($_POST['first_name'], ENT_QUOTES, 'UTF-8') : '' ?>">

    <label for="last_name">Last Name *</label>
    <input type="text" name="last_name" id="last_name" required maxlength="100" value="<?= isset($_POST['last_name']) ? htmlspecialchars($_POST['last_name'], ENT_QUOTES, 'UTF-8') : '' ?>">

    <label for="email">Email *</label>
    <input type="email" name="email" id="email" required maxlength="190" value="<?= isset($_POST['email']) ? htmlspecialchars($_POST['email'], ENT_QUOTES, 'UTF-8') : '' ?>">

    <label for="password">Password *</label>
    <input type="password" name="password" id="password" required minlength="6">

    <label for="contact">Contact (optional)</label>
    <input type="text" name="contact" id="contact" value="<?= isset($_POST['contact']) ? htmlspecialchars($_POST['contact'], ENT_QUOTES, 'UTF-8') : '' ?>">

    <label for="address">Address (optional)</label>
    <input type="text" name="address" id="address" value="<?= isset($_POST['address']) ? htmlspecialchars($_POST['address'], ENT_QUOTES, 'UTF-8') : '' ?>">

    <input type="submit" value="Register">
  </form>
</div>

<!-- Keep these to support the shared AJAX search behavior -->
<main>
  <div id="product-grid" style="display:none;"></div>
  <div id="search-results"></div>
</main>

<footer>
  <div class="footer-content">
    <div class="footer-section">
      <h4>About Us</h4>
      <p>We offer high-quality products with fast delivery and customer satisfaction.</p>
    </div>
    <div class="footer-section">
      <h4>Quick Links</h4>
      <ul>
        <li><a href="#">About</a></li>
        <li><a href="#">Shipping &amp; Returns</a></li>
        <li><a href="#">Privacy Policy</a></li>
        <li><a href="#">Contact</a></li>
      </ul>
    </div>
    <div class="footer-section">
      <h4>Follow Us</h4>
      <div class="social-icons">
        <a href="#"><i class="fab fa-facebook-f"></i></a>
        <a href="#"><i class="fab fa-instagram"></i></a>
        <a href="#"><i class="fab fa-twitter"></i></a>
      </div>
    </div>
  </div>
  <div class="footer-bottom">
    &copy; <?= date('Y') ?> MyWebshop. All rights reserved.
  </div>
</footer>

<!-- Dark Mode + Search (same as index/category/login) -->
<script>
const toggle = document.getElementById('darkModeToggle');
if (localStorage.getItem('theme') === 'dark') {
  document.body.classList.add('dark');
  toggle.textContent = '☀️ Mood';
} else {
  toggle.textContent = '🌙 Mood';
}
toggle.addEventListener('click', () => {
  document.body.classList.toggle('dark');
  const isDark = document.body.classList.contains('dark');
  localStorage.setItem('theme', isDark ? 'dark' : 'light');
  toggle.textContent = isDark ? '☀️ Mood' : '🌙 Mood';
});

// EXACT same AJAX search workflow as index/category
function start() {
  const keyword = document.getElementById("searchinput").value.trim();
  const category = document.getElementById("catg").value;
  const productGrid = document.getElementById("product-grid");
  const searchResults = document.getElementById("search-results");

  if (keyword === "") { return; }

  const xhr = new XMLHttpRequest();
  xhr.open("POST", "search_ajax.php", true);
  xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");

  xhr.onreadystatechange = function () {
    if (xhr.readyState === 4) {
      if (xhr.status === 200) {
        searchResults.innerHTML = xhr.responseText;
        productGrid.style.display = "none";
      } else if (xhr.status === 204) {
        searchResults.innerHTML = "";
        productGrid.style.display = "none";
      } else {
        searchResults.innerHTML = "<p>Search error.</p>";
        productGrid.style.display = "none";
      }
    }
  };
  searchResults.innerHTML = "";
  xhr.send("keyword=" + encodeURIComponent(keyword) + "&category=" + encodeURIComponent(category));
}
</script>

</body>
</html>
