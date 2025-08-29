<?php
/* ================== App bootstrap ================== */
// Simple env-style flags (optional)
$APP_ENV = isset($_ENV['APP_ENV']) ? $_ENV['APP_ENV'] : 'prod'; // 'dev' or 'prod'
$APP_LOG = __DIR__ . '/../_logs/app.log';                       // ideally outside webroot

// Ensure log directory exists
$__logDir = dirname($APP_LOG);
if (!is_dir($__logDir)) { @mkdir($__logDir, 0750, true); }

/* ---------- Error & Exception Handling (top-level) ---------- */
ini_set('display_errors', $APP_ENV === 'dev' ? '1' : '0');
ini_set('log_errors', '1');

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

/* ---------- Session cookie hardening (before session_start) ---------- */
$__secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
session_set_cookie_params([
    'httponly' => true,
    'secure'   => $__secure,
    'samesite' => 'Lax',
]);

session_start();

/* ================== Configuration ================== */
$host = 'localhost';
$db   = 'webshop';
$user = 'Webuser';
$pass = 'Lab2024';

// App options
define('PAGE_SIZE', 20);

/* ---------- Auth state ---------- */
$is_logged_in = isset($_SESSION['user_id']);
$is_admin     = $is_logged_in && (isset($_SESSION['role']) && $_SESSION['role'] === 'admin');
$last_name    = $is_logged_in ? (isset($_SESSION['last_name']) ? $_SESSION['last_name'] : '') : '';

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

/* ================== Database (MySQLi) ================== */
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

$products = [];
$category = isset($_GET['category']) ? trim($_GET['category']) : '';
$pageTitle = $category !== '' ? $category . ' - My Webshop' : 'Category - My Webshop';

try {
    $conn = new mysqli($host, $user, $pass, $db);
    if (!$conn->set_charset('utf8mb4')) {
        app_log('db_charset_warning', 'Failed to set charset to utf8mb4', ['error' => $conn->error]);
    }

    // If no category specified, show nothing
    if ($category !== '') {
        // Prepared query with category filter + page size
        $sql = "
            SELECT p.*, c.name AS category_name
            FROM products p
            JOIN categories c ON p.category_id = c.category_id
            WHERE p.active = 1 AND c.name = ?
            ORDER BY p.created_at DESC
            LIMIT ?
        ";
        $stmt = $conn->prepare($sql);
        $limit = PAGE_SIZE;
        $stmt->bind_param('si', $category, $limit);
        $stmt->execute();
        $result = $stmt->get_result();

        while ($row = $result->fetch_assoc()) {
            $products[] = $row;
        }
        $result->free();
        $stmt->close();
    }
} catch (mysqli_sql_exception $e) {
    app_log('db_error', 'Database operation failed', ['error' => $e->getMessage()]);
    // $products remains empty; UI will show a friendly message
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title><?= htmlspecialchars($pageTitle, ENT_QUOTES, 'UTF-8') ?></title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link rel="stylesheet" href="fontawesome-free-7.0.0-web/css/all.min.css">
  <link rel="stylesheet" href="index.css">
  <script src="search.js" defer></script>
</head>
<body>

<!-- HEADER -->
<header>
  <a href="index.php"><img src="images/logo.png" id="logo" alt="Logo"></a>

  <!-- Search Bar -->
  <div class="search-container">
    <form class="search-bar" onsubmit="start(); return false;">
      <select name="catg" id="catg" aria-label="Category">
        <option value="">All Categories</option>
        <option value="Clothing"   <?= $category==='Clothing' ? 'selected' : '' ?>>Clothing</option>
        <option value="Electronics"<?= $category==='Electronics' ? 'selected' : '' ?>>Electronics</option>
        <option value="Gifts"      <?= $category==='Gifts' ? 'selected' : '' ?>>Gifts</option>
        <option value="Pets"       <?= $category==='Pets' ? 'selected' : '' ?>>Pets</option>
      </select>
      <input type="text" id="searchinput" placeholder="Search..." aria-label="Search" />
      <button type="submit" title="Search" aria-label="Search"><i class="fas fa-search"></i></button>
    </form>
  </div>

  <div class="user-links">
    <?php if ($is_logged_in): ?>
      <span>Hello, <?= htmlspecialchars($last_name, ENT_QUOTES, 'UTF-8') ?></span>
      <?php if ($is_admin): ?>
        <a href="admin_dashboard.php" title="Admin Panel">Admin Panel</a>
      <?php endif; ?>
      <a href="logout.php" title="Logout"><i class="fas fa-sign-out-alt"></i> Logout</a>

      <div class="cart-dropdown">
        <a href="cart.php" title="Cart"><i class="fas fa-cart-shopping"></i> Cart</a>
        <div class="cart-dropdown-content">
          <a href="orders.php"><i class="fas fa-box"></i> My Orders</a>
        </div>
      </div>
    <?php else: ?>
      <a href="register.php" title="Register"><i class="fas fa-uniregistry"></i> Register</a>
      <a href="login.php" title="Login"><i class="fas fa-sign-in-alt"></i> Login</a>
    <?php endif; ?>
    <a id="darkModeToggle" title="Toggle dark mode">🌙 Mood</a>
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

<h2 style="text-align:center; margin-top:20px;"><?= htmlspecialchars($category, ENT_QUOTES, 'UTF-8') ?></h2>

<main>
  <!-- Product grid MUST have this id so search.js logic can toggle it -->
  <div class="product-grid" id="product-grid">
    <?php if ($category === ''): ?>
      <div class="empty-state">
        <h2>Please choose a category</h2>
      </div>
    <?php elseif (empty($products)): ?>
      <div class="empty-state">
        <h2>No products found in this category.</h2>
      </div>
    <?php else: ?>
      <?php foreach ($products as $row): ?>
        <div class="product-card">
          <img src="<?= htmlspecialchars(isset($row['image']) ? $row['image'] : '', ENT_QUOTES, 'UTF-8') ?>"
               alt="<?= htmlspecialchars(isset($row['name']) ? $row['name'] : 'Product', ENT_QUOTES, 'UTF-8') ?>">
          <h3><?= htmlspecialchars(isset($row['name']) ? $row['name'] : '', ENT_QUOTES, 'UTF-8') ?></h3>
          <p><?= htmlspecialchars(isset($row['category_name']) ? $row['category_name'] : '', ENT_QUOTES, 'UTF-8') ?></p>
          <p>€<?= number_format((float)(isset($row['price']) ? $row['price'] : 0), 2) ?></p>

          <a href="product.php?id=<?= (int)(isset($row['product_id']) ? $row['product_id'] : 0) ?>">View</a>

          <?php if ($is_logged_in): ?>
            <form method="post" action="cart.php" style="display:inline;">
              <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
              <input type="hidden" name="product_id" value="<?= (int)(isset($row['product_id']) ? $row['product_id'] : 0) ?>">
              <input type="hidden" name="quantity" value="1">
              <button type="submit" name="add_to_cart" id="cbttn1" aria-label="Add to cart">
                <i class="fas fa-cart-plus"></i>
              </button>
            </form>
          <?php endif; ?>
        </div>
      <?php endforeach; ?>
    <?php endif; ?>
  </div>

  <!-- This container is required for AJAX search results to appear -->
  <div id="search-results"></div>
</main>

<!-- FOOTER -->
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
        <a href="#" aria-label="Facebook"><i class="fab fa-facebook-f"></i></a>
        <a href="#" aria-label="Instagram"><i class="fab fa-instagram"></i></a>
        <a href="#" aria-label="Twitter"><i class="fab fa-twitter"></i></a>
      </div>
    </div>
  </div>
  <div class="footer-bottom">
    &copy; <?= date('Y') ?> MyWebshop. All rights reserved.
  </div>
</footer>

<!-- Dark Mode + Search JS (same behavior as index) -->
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

// EXACT same search workflow as index.php
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
        productGrid.style.display = "flex";
      } else {
        searchResults.innerHTML = "<p>Search error.</p>";
        productGrid.style.display = "flex";
      }
    }
  };
  searchResults.innerHTML = "";
  xhr.send("keyword=" + encodeURIComponent(keyword) + "&category=" + encodeURIComponent(category));
}
</script>

</body>
</html>
<?php
if (isset($conn) && $conn instanceof mysqli) { $conn->close(); }
?>
