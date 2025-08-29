<?php
session_start();
require 'config.php'; // must provide $conn (MySQLi)

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
        'user'  => isset($_SESSION['user_id']) ? $_SESSION['user_id'] : null,
    ]);
    http_response_code(500);
    if (!headers_sent()) {
        header('Content-Type: text/html; charset=utf-8');
    }
    echo '<h1>Something went wrong</h1><p>Please try again later.</p>';
    exit;
});
register_shutdown_function(function () {
    $e = error_get_last();
    if ($e && in_array($e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
        app_log('fatal', $e['message'], ['file'=>$e['file'], 'line'=>$e['line']]);
        http_response_code(500);
        if (!headers_sent()) {
            header('Content-Type: text/html; charset=utf-8');
        }
        echo '<h1>Unexpected error</h1><p>Please try again later.</p>';
    }
});

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

/* ---------- Login handling ---------- */
$error = '';
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT); // throw exceptions

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    // CSRF check
    $token = isset($_POST['csrf_token']) ? $_POST['csrf_token'] : '';
    if (!hash_equals($_SESSION['csrf_token'], $token)) {
        app_log('csrf', 'CSRF token mismatch on login');
        http_response_code(400);
        $error = 'Invalid request.';
    } else {
        // Basic normalization
        $email = isset($_POST['email']) ? trim($_POST['email']) : '';
        $password = isset($_POST['password']) ? $_POST['password'] : '';

        // Validate email shape before querying
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $error = 'Please enter a valid email address.';
        } elseif ($password === '') {
            $error = 'Please enter your password.';
        } else {
            try {
                $stmt = $conn->prepare("SELECT user_id, email, role, last_name, password FROM users WHERE email = ? AND active = 1");
                $stmt->bind_param("s", $email);
                $stmt->execute();
                $result = $stmt->get_result();
                $user = $result ? $result->fetch_assoc() : null;

                if ($user && password_verify($password, $user['password'])) {
                    // Regenerate session ID on login
                    session_regenerate_id(true);
                    $_SESSION['user_id']   = $user['user_id'];
                    $_SESSION['email']     = $user['email'];
                    $_SESSION['role']      = $user['role'];
                    $_SESSION['last_name'] = $user['last_name'];

                    header("Location: index.php");
                    exit;
                } else {
                    // Optional: small delay to mitigate brute force
                    usleep(200000); // 200ms
                    $error = "Invalid email or password.";
                }
                if ($result) { $result->free(); }
                $stmt->close();
            } catch (mysqli_sql_exception $e) {
                app_log('db_login_error', 'Login query failed', ['error' => $e->getMessage()]);
                // Generic error for user
                $error = 'Login temporarily unavailable. Please try again later.';
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Login — My Webshop</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link rel="stylesheet" href="index.css">
  <link rel="stylesheet" href="login.css">
  <link rel="stylesheet" href="fontawesome-free-7.0.0-web/css/all.min.css">
  <script src="search.js" defer></script>
</head>
<body>

<!-- HEADER -->
<header>
  <a href="index.php"><img src="images/logo.png" id="logo" alt="Logo"></a>

  <!-- Search Bar (same behavior as index/category) -->
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
      <button type="submit" title="Search" aria-label="Search">
        <i class="fas fa-search"></i>
      </button>
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
  <h2>Login to Your Account</h2>
  <?php if (!empty($error)): ?>
    <p style="color: red;"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></p>
  <?php endif; ?>

  <form method="post" novalidate>
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">

    <label for="email">Email Address</label>
    <input type="email" name="email" id="email" required autocomplete="username" inputmode="email">

    <label for="password">Password</label>
    <input type="password" name="password" id="password" required autocomplete="current-password">

    <input type="submit" value="Login">
    <div class="login-links">
      <a href="#">Forgot your password?</a>
      <a href="register.php">Register</a>
    </div>
  </form>
</div>

<!-- Containers to support search behavior like index/category -->
<main>
  <!-- No product grid here, but keep a placeholder to avoid JS errors if you reuse scripts -->
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

<!-- Dark Mode + Search JS (same as index/category) -->
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
