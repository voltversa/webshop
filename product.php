<?php
/* ================== App bootstrap ================== */
$APP_ENV = $_ENV['APP_ENV'] ?? 'prod';                       // 'dev' or 'prod'
$APP_LOG = __DIR__ . '/../_logs/app.log';                    // ideally outside webroot
if (!is_dir(dirname($APP_LOG))) { @mkdir(dirname($APP_LOG), 0750, true); }

/* ---------- Error & Exception Handling (top-level) ---------- */
ini_set('display_errors', $APP_ENV === 'dev' ? '1' : '0');
ini_set('log_errors', '1');
if (!function_exists('app_log')) {
    function app_log($level, $message, $ctx = []) {
        global $APP_LOG;
        $entry = [
            'ts'     => date('c'),
            'level'  => $level,
            'ip'     => $_SERVER['REMOTE_ADDR'] ?? null,
            'method' => $_SERVER['REQUEST_METHOD'] ?? null,
            'uri'    => $_SERVER['REQUEST_URI'] ?? null,
            'msg'    => $message,
            'ctx'    => $ctx,
        ];
        error_log(json_encode($entry, JSON_UNESCAPED_SLASHES) . PHP_EOL, 3, $APP_LOG);
    }
}
set_error_handler(function ($severity, $message, $file, $line) {
    if (!(error_reporting() & $severity)) return false;
    app_log('php_error', $message, ['file'=>$file,'line'=>$line,'severity'=>$severity]);
    throw new ErrorException($message, 0, $severity, $file, $line);
});
set_exception_handler(function ($e) {
    app_log('exception', $e->getMessage(), [
        'file'=>$e->getFile(),'line'=>$e->getLine(),
        'trace'=>array_slice(explode("\n", $e->getTraceAsString()), 0, 20),
        'user'=>$_SESSION['user_id'] ?? null,
    ]);
    http_response_code(500);
    if (!headers_sent()) header('Content-Type: text/html; charset=utf-8');
    echo '<h1>Something went wrong</h1><p>Please try again later.</p>';
    exit;
});
register_shutdown_function(function () {
    $e = error_get_last();
    if ($e && in_array($e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
        app_log('fatal', $e['message'], ['file'=>$e['file'],'line'=>$e['line']]);
        http_response_code(500);
        if (!headers_sent()) header('Content-Type: text/html; charset=utf-8');
        echo '<h1>Unexpected error</h1><p>Please try again later.</p>';
    }
});

/* ---------- Session cookie hardening (before session_start) ---------- */
$__secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
session_set_cookie_params(['httponly'=>true,'secure'=>$__secure,'samesite'=>'Lax']);
session_start();

/* ---------- Security headers ---------- */
header('Content-Type: text/html; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
header('Cross-Origin-Opener-Policy: same-origin');
// Optional CSP:
// header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; font-src 'self'; frame-ancestors 'self';");

/* ---------- CSRF token for forms (Add to Cart posts to cart.php) ---------- */
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf = $_SESSION['csrf_token'];

/* ---------- DB ---------- */
require 'config.php';                 // provides $conn (MySQLi)
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT); // throw exceptions

/* ---------- Auth state ---------- */
$is_logged_in = isset($_SESSION['user_id']);

/* ---------- Validate & load product ---------- */
$product = null;
try {
    $product_id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
    if ($product_id <= 0) {
        app_log('product_bad_id', 'Invalid product id', ['raw'=>$_GET['id'] ?? null]);
        header('Location: index.php');
        exit;
    }

    $sql = "
        SELECT p.*, c.name AS category_name
        FROM products p
        JOIN categories c ON p.category_id = c.category_id
        WHERE p.product_id = ? AND p.active = 1
    ";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("i", $product_id);
    $stmt->execute();
    $res = $stmt->get_result();
    $product = $res ? $res->fetch_assoc() : null;
    if ($res) $res->free();
    $stmt->close();

    if (!$product) {
        app_log('product_not_found', 'Active product not found', ['product_id'=>$product_id]);
        header('Location: index.php');
        exit;
    }
} catch (mysqli_sql_exception $e) {
    app_log('product_query_error', 'Failed to fetch product', ['error'=>$e->getMessage()]);
    http_response_code(500);
    $product = null;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title><?= htmlspecialchars(($product['name'] ?? 'Product') . ' — My Webshop', ENT_QUOTES, 'UTF-8') ?></title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <link rel="stylesheet" href="index.css">
    <link rel="stylesheet" href="fontawesome-free-7.0.0-web/css/all.min.css">
    <style>
      .product-page { max-width: 1000px; margin: auto; padding: 20px; }
      .product-flex { display:flex; gap:20px; flex-wrap:wrap; align-items:flex-start; }
      .product-img { flex:1; min-width: 300px; }
      .product-img img { max-width:100%; border:1px solid #ccc; border-radius:6px; }
      .product-info { flex:1; min-width: 300px; }
      .price { font-size: 1.25rem; font-weight: bold; margin: 8px 0; }
      #cbttn1 { display:inline-flex; align-items:center; gap:8px; }
    </style>
</head>
<body>

<header>
    <a href="index.php"><img src="images/logo.png" id="logo" alt="Logo"></a>
    <div class="user-links">
        <a href="index.php"><i class="fas fa-home"></i> Home</a>
        <?php if ($is_logged_in): ?>
            <a href="cart.php"><i class="fas fa-shopping-cart"></i> Cart</a>
            <a href="logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a>
        <?php else: ?>
            <a href="login.php"><i class="fas fa-sign-in-alt"></i> Login</a>
            <a href="register.php"><i class="fas fa-user-plus"></i> Register</a>
        <?php endif; ?>
        <a id="darkModeToggle" title="Toggle dark mode">🌙 Mood</a>
    </div>
</header>

<main class="product-page">
  <?php if (!$product): ?>
    <p>We couldn’t load this product right now. Please try again later.</p>
  <?php else: ?>
    <div class="product-flex">
        <!-- Product Image -->
        <div class="product-img">
            <img src="<?= htmlspecialchars($product['image'] ?? '', ENT_QUOTES, 'UTF-8') ?>"
                 alt="<?= htmlspecialchars($product['name'] ?? 'Product', ENT_QUOTES, 'UTF-8') ?>">
        </div>

        <!-- Product Info -->
        <div class="product-info">
            <h1><?= htmlspecialchars($product['name'] ?? '', ENT_QUOTES, 'UTF-8') ?></h1>
            <p><strong>Category:</strong> <?= htmlspecialchars($product['category_name'] ?? '', ENT_QUOTES, 'UTF-8') ?></p>
            <p class="price"><strong>Price:</strong> €<?= number_format((float)($product['price'] ?? 0), 2) ?></p>
            <p><strong>Description:</strong><br><?= nl2br(htmlspecialchars($product['description'] ?? 'No description available.', ENT_QUOTES, 'UTF-8')) ?></p>

            <?php if ($is_logged_in): ?>
                <!-- Add to Cart Form -->
                <form action="cart.php" method="post" style="margin-top: 20px;">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
                    <input type="hidden" name="product_id" value="<?= (int)($product['product_id'] ?? 0) ?>">
                    
                    <label for="quantity">Quantity:</label>
                    <input type="number" id="quantity" name="quantity" value="1" min="1" style="width: 80px;">

                    <button type="submit" name="add_to_cart" id="cbttn1">
                        <i class="fas fa-cart-plus"></i> Add to Cart
                    </button>
                </form>
            <?php else: ?>
                <p style="margin-top: 16px;">
                  <a href="login.php">Log in</a> to add this product to your cart.
                </p>
            <?php endif; ?>
        </div>
    </div>
  <?php endif; ?>
</main>

<script>
const toggle = document.getElementById('darkModeToggle');
// Restore theme from localStorage
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
</script>

</body>
</html>
