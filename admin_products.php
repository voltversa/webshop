<?php
/* ================== App bootstrap ================== */
$APP_ENV = $_ENV['APP_ENV'] ?? 'prod';                 // 'dev' or 'prod'
$APP_LOG = __DIR__ . '/../_logs/app.log';              // ideally outside webroot
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
        'trace'=>array_slice(explode("\n",$e->getTraceAsString()),0,20),
        'user'=>$_SESSION['user_id'] ?? null,
    ]);
    http_response_code(500);
    if (!headers_sent()) header('Content-Type: text/html; charset=utf-8');
    echo '<h1>Something went wrong</h1><p>Please try again later.</p>';
    exit;
});
register_shutdown_function(function () {
    $e = error_get_last();
    if ($e && in_array($e['type'], [E_ERROR,E_PARSE,E_CORE_ERROR,E_COMPILE_ERROR], true)) {
        app_log('fatal', $e['message'], ['file'=>$e['file'],'line'=>$e['line']]);
        http_response_code(500);
        if (!headers_sent()) header('Content-Type: text/html; charset=utf-8');
        echo '<h1>Unexpected error</h1><p>Please try again later.</p>';
    }
});

/* ---------- Session cookie hardening ---------- */
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
// Optional CSP after auditing:
// header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; font-src 'self'; frame-ancestors 'self';");

/* ---------- CSRF token ---------- */
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf = $_SESSION['csrf_token'];

/* ---------- Admin check (after session_start) ---------- */
require_once 'admin_check.php';

/* ---------- DB ---------- */
require_once 'config.php';                               // $conn (MySQLi)
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

/* ---------- Helpers ---------- */
function redirect_self() { header('Location: '.$_SERVER['PHP_SELF'], true, 303); exit; }
function require_csrf_or_400() {
    if (!hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token'] ?? '')) {
        app_log('csrf', 'CSRF token mismatch on admin_products');
        http_response_code(400);
        exit('Invalid request.');
    }
}

/* ================== Handle POST actions ================== */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf_or_400();
    $flash = '';
    try {
        $pid = isset($_POST['product_id']) ? (int)$_POST['product_id'] : 0;
        if ($pid <= 0) { $flash = 'Invalid product ID.'; $_SESSION['flash'] = $flash; redirect_self(); }

        if (isset($_POST['toggle_active'])) {
            $stmt = $conn->prepare("UPDATE products SET active = NOT active WHERE product_id = ?");
            $stmt->bind_param("i", $pid);
            $stmt->execute();
            $stmt->close();
            $flash = 'Product status updated.';
        }

        if (isset($_POST['delete'])) {
            $stmt = $conn->prepare("DELETE FROM products WHERE product_id = ?");
            $stmt->bind_param("i", $pid);
            try {
                $stmt->execute();
                $flash = 'Product deleted.';
            } catch (mysqli_sql_exception $e) {
                // Likely foreign key constraint (order_items references products)
                if (strpos($e->getMessage(), '1451') !== false) {
                    $flash = 'Cannot delete: product is referenced by other records.';
                } else {
                    throw $e;
                }
            } finally {
                $stmt->close();
            }
        }
    } catch (Throwable $e) {
        app_log('admin_products_post_error', 'Action failed', ['error'=>$e->getMessage()]);
        $flash = $flash ?: 'Operation failed. Please try again.';
    }
    $_SESSION['flash'] = $flash;
    redirect_self(); // PRG
}

/* ================== Fetch products ================== */
$products = [];
try {
    $sql = "SELECT p.product_id, p.name, p.price, p.active, p.created_at, c.name AS category_name
            FROM products p
            JOIN categories c ON p.category_id = c.category_id
            ORDER BY p.created_at DESC";
    $result = $conn->query($sql);
    while ($row = $result->fetch_assoc()) { $products[] = $row; }
    $result->free();
} catch (mysqli_sql_exception $e) {
    app_log('admin_products_fetch_error', 'Failed to load products', ['error'=>$e->getMessage()]);
}

/* Flash message */
$flash = $_SESSION['flash'] ?? '';
unset($_SESSION['flash']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Product Management</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link rel="stylesheet" href="index.css">
  <link rel="stylesheet" href="fontawesome-free-7.0.0-web/css/all.min.css">
  <style>
    .admin-container { max-width: 1000px; margin: auto; padding: 20px; }
    .admin-container h2 { margin-bottom: 15px; }
    .product-table { width: 100%; border-collapse: collapse; }
    .product-table th, .product-table td { border: 1px solid #ccc; padding: 10px; text-align: center; }
    .btn { background: #2d89ef; color: white; border: none; padding: 6px 12px; border-radius: 5px; margin: 2px; cursor: pointer; }
    .btn:hover { background: #1a5fbe; }
    .btn-danger { background: #e74c3c; }
    .btn-danger:hover { background: #c0392b; }
    a.btn-link { text-decoration: none; padding: 6px 12px; background: #4CAF50; color: white; border-radius: 5px; display: inline-block; margin-right: 5px; }
    a.btn-link:hover { background: #388e3c; }
    .actions form { display: inline-block; }
    .flash { margin:10px 0; padding:10px; border-radius:6px; background:#eef6ff; color:#0b4f8a; border:1px solid #b6daff; }
    body.dark .flash { background:#16324a; color:#e6f1ff; border-color:#204a6b; }
  </style>
</head>
<body>

<header>
  <a href="index.php"><img src="images/logo.png" id="logo" alt="Logo"></a>
  <div class="user-links">
    <a href="admin_dashboard.php"><i class="fas fa-arrow-left"></i> Dashboard</a>
    <a href="logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a>
    <a id="darkModeToggle" title="Toggle dark mode">🌙 Mood</a>
  </div>
</header>

<div class="admin-container">
  <h2>Product Management</h2>

  <?php if ($flash): ?>
    <div class="flash"><?= htmlspecialchars($flash, ENT_QUOTES, 'UTF-8') ?></div>
  <?php endif; ?>

  <a href="add_product.php" class="btn-link"><i class="fas fa-plus"></i> Add New Product</a>

  <table class="product-table">
    <tr>
      <th>ID</th>
      <th>Name</th>
      <th>Price</th>
      <th>Category</th>
      <th>Status</th>
      <th>Actions</th>
    </tr>
    <?php foreach ($products as $p): ?>
    <tr>
      <td><?= (int)$p['product_id'] ?></td>
      <td><?= htmlspecialchars($p['name'], ENT_QUOTES, 'UTF-8') ?></td>
      <td>€<?= number_format((float)$p['price'], 2) ?></td>
      <td><?= htmlspecialchars($p['category_name'], ENT_QUOTES, 'UTF-8') ?></td>
      <td><?= ((int)$p['active'] === 1) ? 'Active' : 'Inactive' ?></td>
      <td class="actions">
        <a href="edit_product.php?id=<?= (int)$p['product_id'] ?>" class="btn-link"><i class="fas fa-edit"></i> Edit</a>

        <form method="post" style="display:inline;">
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
          <input type="hidden" name="product_id" value="<?= (int)$p['product_id'] ?>">
          <button name="toggle_active" class="btn" title="Toggle active status">
            <?= ((int)$p['active'] === 1) ? 'Deactivate' : 'Activate' ?>
          </button>
        </form>

        <form method="post" style="display:inline;" onsubmit="return confirm('Are you sure you want to delete this product? This cannot be undone.')">
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
          <input type="hidden" name="product_id" value="<?= (int)$p['product_id'] ?>">
          <button name="delete" class="btn btn-danger" title="Delete this product">
            <i class="fas fa-trash-alt"></i> Delete
          </button>
        </form>
      </td>
    </tr>
    <?php endforeach; ?>
  </table>
</div>

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
</script>

</body>
</html>
