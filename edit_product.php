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
    if (!(error_reporting() & $severity)) return false; // respect @
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

/* ---------- CSRF token ---------- */
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf = $_SESSION['csrf_token'];

/* ---------- Admin check & DB ---------- */
require_once 'admin_check.php';      // must run after session_start
require_once 'config.php';           // $conn (MySQLi)
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

/* ================== Load product & categories ================== */
$success = false;
$errors  = [];

$id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
if ($id <= 0) {
    app_log('edit_product_bad_id', 'Invalid product id', ['raw'=>$_GET['id'] ?? null]);
    header('Location: admin_products.php');
    exit;
}

try {
    // Fetch product
    $stmt = $conn->prepare("SELECT * FROM products WHERE product_id = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $product = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    if (!$product) {
        app_log('edit_product_not_found', 'No product', ['product_id'=>$id]);
        header('Location: admin_products.php');
        exit;
    }

    // Fetch categories
    $categories = [];
    $res = $conn->query("SELECT category_id, name FROM categories ORDER BY name");
    while ($row = $res->fetch_assoc()) { $categories[] = $row; }
    $res->free();
} catch (mysqli_sql_exception $e) {
    app_log('edit_product_fetch_error', 'Failed loading product/categories', ['error'=>$e->getMessage(),'product_id'=>$id]);
    $errors[] = 'Unable to load product. Please try again later.';
}

/* ================== Handle update ================== */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF check
    $token = $_POST['csrf_token'] ?? '';
    if (!hash_equals($_SESSION['csrf_token'], $token)) {
        app_log('csrf', 'CSRF mismatch on edit product', ['product_id'=>$id]);
        http_response_code(400);
        $errors[] = 'Invalid request.';
    } else {
        // Collect & validate
        $name        = trim($_POST['name'] ?? '');
        $description = trim($_POST['description'] ?? '');
        $price       = isset($_POST['price']) ? (float)$_POST['price'] : 0.0;
        $category_id = isset($_POST['category_id']) ? (int)$_POST['category_id'] : 0;
        $image       = trim($_POST['image'] ?? '');

        if ($name === '')                $errors[] = 'Name is required.';
        if (!is_numeric($_POST['price'] ?? '')) $errors[] = 'Price must be numeric.';
        if ($price < 0)                  $errors[] = 'Price cannot be negative.';
        if ($category_id <= 0)           $errors[] = 'Please choose a category.';

        // Ensure category exists
        if ($category_id > 0) {
            try {
                $chk = $conn->prepare("SELECT 1 FROM categories WHERE category_id = ?");
                $chk->bind_param("i", $category_id);
                $chk->execute();
                $ok = (bool)$chk->get_result()->fetch_row();
                $chk->close();
                if (!$ok) $errors[] = 'Selected category does not exist.';
            } catch (mysqli_sql_exception $e) {
                app_log('edit_product_cat_check', 'Category check failed', ['error'=>$e->getMessage()]);
                $errors[] = 'Unable to validate category.';
            }
        }

        // Update if valid
        if (empty($errors)) {
            try {
                $stmt = $conn->prepare("UPDATE products SET name=?, description=?, price=?, category_id=?, image=? WHERE product_id=?");
                $stmt->bind_param("ssdisi", $name, $description, $price, $category_id, $image, $id);
                $stmt->execute();
                $stmt->close();

                // Reload product for updated values
                $stmt = $conn->prepare("SELECT * FROM products WHERE product_id = ?");
                $stmt->bind_param("i", $id);
                $stmt->execute();
                $product = $stmt->get_result()->fetch_assoc();
                $stmt->close();

                $success = true;
            } catch (mysqli_sql_exception $e) {
                app_log('edit_product_update_error', 'Update failed', ['error'=>$e->getMessage(),'product_id'=>$id]);
                $errors[] = 'Update failed. Please try again.';
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Edit Product</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link rel="stylesheet" href="index.css">
  <link rel="stylesheet" href="fontawesome-free-7.0.0-web/css/all.min.css">
  <style>
    .admin-container { max-width: 800px; margin: auto; padding: 20px; }
    .admin-container h2 { margin-bottom: 15px; }
    form label { display:block; margin-top: 10px; }
    input, select, textarea { width:100%; padding:8px; margin-top:5px; border-radius:4px; border:1px solid #ccc; }
    button, .cancel-btn { margin-top:15px; padding:10px 16px; background-color:#2d89ef; color:#fff; border:none; border-radius:5px; cursor:pointer; display:inline-block; }
    button:hover { background-color:#1a5fbe; }
    .cancel-btn { background-color:#aaa; text-decoration:none; }
    .cancel-btn:hover { background-color:#888; }
    .success-message { background:#d4edda; color:#155724; border:1px solid #c3e6cb; padding:10px; border-radius:5px; margin-bottom:15px; }
    .error { background:#fdecea; color:#b71c1c; border:1px solid #f5c2c7; padding:10px; border-radius:6px; margin-bottom:10px; }
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
  <h2>Edit Product</h2>

  <?php if (!empty($errors)): ?>
    <div class="error">
      <?php foreach ($errors as $e) echo '<div>'.htmlspecialchars($e, ENT_QUOTES, 'UTF-8').'</div>'; ?>
    </div>
  <?php endif; ?>

  <?php if ($success): ?>
    <div class="success-message">✅ Product updated successfully!</div>
  <?php endif; ?>

  <form method="post" novalidate>
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">

    <label>Name</label>
    <input type="text" name="name" value="<?= htmlspecialchars($product['name'] ?? '', ENT_QUOTES, 'UTF-8') ?>" required>

    <label>Description</label>
    <textarea name="description"><?= htmlspecialchars($product['description'] ?? '', ENT_QUOTES, 'UTF-8') ?></textarea>

    <label>Price (€)</label>
    <input type="number" name="price" step="0.01" min="0" value="<?= htmlspecialchars((string)($product['price'] ?? '0.00'), ENT_QUOTES, 'UTF-8') ?>" required>

    <label>Category</label>
    <select name="category_id" required>
      <option value="">-- Select --</option>
      <?php foreach ($categories as $cat): ?>
        <option value="<?= (int)$cat['category_id'] ?>" <?= ((int)($product['category_id'] ?? 0) === (int)$cat['category_id']) ? 'selected' : '' ?>>
          <?= htmlspecialchars($cat['name'], ENT_QUOTES, 'UTF-8') ?>
        </option>
      <?php endforeach; ?>
    </select>

    <label>Image URL</label>
    <input type="text" name="image" value="<?= htmlspecialchars($product['image'] ?? '', ENT_QUOTES, 'UTF-8') ?>">

    <button type="submit"><i class="fas fa-save"></i> Update Product</button>
    <a href="admin_products.php" class="cancel-btn">Cancel</a>
  </form>
</div>

<script>
const toggle = document.getElementById('darkModeToggle');
if (localStorage.getItem('theme') === 'dark') {
  document.body.classList.add('dark');
  toggle.textContent = '☀️ Mood';
} else {
  document.body.textContent !== null; 
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
