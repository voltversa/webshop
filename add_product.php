<?php
/* ================== App bootstrap ================== */
$APP_ENV = $_ENV['APP_ENV'] ?? 'prod';                 // 'dev' or 'prod'
$APP_LOG = __DIR__ . '/../_logs/app.log';              // ideally outside webroot
$__logDir = dirname($APP_LOG);
if (!is_dir($__logDir) && !@mkdir($__logDir, 0750, true)) {
  // Fallback if logs dir isn't writable/creatable
  $APP_LOG = sys_get_temp_dir() . '/app.log';
}

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
    echo 'Something went wrong<br>Please try again later.';
    exit;
});
register_shutdown_function(function () {
    $e = error_get_last();
    if ($e && in_array($e['type'], [E_ERROR,E_PARSE,E_CORE_ERROR,E_COMPILE_ERROR], true)) {
        app_log('fatal', $e['message'], ['file'=>$e['file'],'line'=>$e['line']]);
        http_response_code(500);
        if (!headers_sent()) header('Content-Type: text/html; charset=utf-8');
        echo 'Unexpected error<br>Please try again later.';
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
// Optional CSP after auditing assets:
// header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; font-src 'self'; frame-ancestors 'self';");

/* ---------- CSRF token ---------- */
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf = $_SESSION['csrf_token'];

/* ---------- Admin check & DB ---------- */
require_once 'admin_check.php';      // must run after session_start
require_once 'config.php';           // provides $conn (MySQLi)
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

/* ================== Fetch categories ================== */
$categories = [];
try {
    $res = $conn->query("SELECT category_id, name FROM categories ORDER BY name");
    while ($row = $res->fetch_assoc()) { $categories[] = $row; }
    $res->free();
} catch (mysqli_sql_exception $e) {
    app_log('add_product_load_categories', 'Failed to load categories', ['error'=>$e->getMessage()]);
}

/* ================== Handle POST ================== */
$success = false;
$errors  = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF
    $token = $_POST['csrf_token'] ?? '';
    if (!hash_equals($_SESSION['csrf_token'], $token)) {
        app_log('csrf', 'CSRF token mismatch on add_product');
        http_response_code(400);
        $errors[] = 'Invalid request.';
    } else {
        // Collect inputs
        $name        = trim($_POST['name'] ?? '');
        $description = trim($_POST['description'] ?? '');
        $priceStr    = $_POST['price'] ?? '';
        $price       = is_numeric($priceStr) ? (float)$priceStr : null;
        $category_id = isset($_POST['category_id']) ? (int)$_POST['category_id'] : 0;
        $image       = trim($_POST['image'] ?? '');

        // Validate
        if ($name === '')                    $errors[] = 'Name is required.';
        if ($price === null)                 $errors[] = 'Price must be numeric.';
        if ($price !== null && $price < 0)   $errors[] = 'Price cannot be negative.';
        if ($category_id <= 0)               $errors[] = 'Please choose a category.';

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
                app_log('add_product_cat_check', 'Category check failed', ['error'=>$e->getMessage()]);
                $errors[] = 'Unable to validate category.';
            }
        }

        // Insert
        if (empty($errors)) {
            try {
                $stmt = $conn->prepare("
                    INSERT INTO products (name, description, price, category_id, image, active, created_at)
                    VALUES (?, ?, ?, ?, ?, 1, NOW())
                ");
                // EXACTLY 5 placeholders -> 5 type letters
                // s (name), s (description), d (price), i (category_id), s (image)
                $stmt->bind_param("ssdis", $name, $description, $price, $category_id, $image);
                $stmt->execute();
                $stmt->close();

                $success = true;
                // Optional: clear POST for fresh form
                $_POST = [];
            } catch (mysqli_sql_exception $e) {
                app_log('add_product_insert_error', 'Insert failed', ['error'=>$e->getMessage()]);
                $errors[] = 'Could not save product. Please try again.';
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Add Product</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link rel="stylesheet" href="index.css">
  <link rel="stylesheet" href="fontawesome-free-7.0.0-web/css/all.min.css">
  <style>
    .admin-form-container {
      max-width: 600px; margin: 40px auto; background-color: var(--bg);
      color: var(--text); border: 1px solid var(--border); border-radius: 10px;
      padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1);
    }
    .admin-form-container h2 { text-align: center; margin-bottom: 20px; }
    .admin-form-container form { display: flex; flex-direction: column; }
    .admin-form-container label { margin-top: 15px; }
    .admin-form-container input, .admin-form-container select, .admin-form-container textarea {
      padding: 10px; margin-top: 5px; border-radius: 5px; border: 1px solid var(--border);
      background-color: var(--input-bg); color: var(--text);
    }
    .admin-form-container button, .admin-form-container a {
      margin-top: 20px; padding: 10px; border: none; background-color: var(--accent);
      color: white; text-align: center; text-decoration: none; border-radius: 5px;
      cursor: pointer; transition: background-color 0.3s;
    }
    .admin-form-container a { background-color: gray; }
    .admin-form-container button:hover, .admin-form-container a:hover { background-color: var(--accent-dark); }
    .success-message { background:#d4edda; color:#155724; border:1px solid #c3e6cb; padding:12px; border-radius:5px; margin-bottom:15px; text-align:center; }
    .error { background:#fdecea; color:#b71c1c; border:1px solid #f5c2c7; padding:10px; border-radius:6px; margin-bottom:10px; }
    :root { --bg:#fff; --text:#000; --border:#ccc; --input-bg:#f9f9f9; --accent:#007BFF; --accent-dark:#0056b3; }
    body.dark :root { --bg:#121212; --text:#f1f1f1; --border:#444; --input-bg:#1e1e1e; --accent:#2196F3; --accent-dark:#1565C0; }
  </style>
</head>
<body>

<header>
  <a href="index.php"><img src="images/logo.png" id="logo" alt="Logo"></a>
  <div class="user-links">
    <a href="admin_dashboard.php"><i class="fas fa-tools"></i> Admin Panel</a>
    <a id="darkModeToggle" title="Toggle dark mode">🌙 Mood</a>
    <a href="logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a>
  </div>
</header>

<div class="admin-form-container">
  <h2>Add New Product</h2>

  <?php if (!empty($errors)): ?>
    <div class="error">
      <?php foreach ($errors as $e) echo '<div>'.htmlspecialchars($e, ENT_QUOTES, 'UTF-8').'</div>'; ?>
    </div>
  <?php endif; ?>

  <?php if ($success): ?>
    <div class="success-message">✅ Product added successfully!</div>
  <?php endif; ?>

  <form method="post" novalidate>
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">

    <label>Name</label>
    <input type="text" name="name" required value="<?= htmlspecialchars($_POST['name'] ?? '', ENT_QUOTES, 'UTF-8') ?>">

    <label>Description</label>
    <textarea name="description" rows="4"><?= htmlspecialchars($_POST['description'] ?? '', ENT_QUOTES, 'UTF-8') ?></textarea>

    <label>Price (€)</label>
    <input type="number" step="0.01" min="0" name="price" required value="<?= htmlspecialchars($_POST['price'] ?? '', ENT_QUOTES, 'UTF-8') ?>">

    <label>Category</label>
    <select name="category_id" required>
      <option value="">-- Select --</option>
      <?php foreach ($categories as $cat): ?>
        <option value="<?= (int)$cat['category_id'] ?>" <?= ((int)$cat['category_id'] === (int)($_POST['category_id'] ?? 0)) ? 'selected' : '' ?>>
          <?= htmlspecialchars($cat['name'], ENT_QUOTES, 'UTF-8') ?>
        </option>
      <?php endforeach; ?>
    </select>

    <label>Image URL</label>
    <input type="text" name="image" placeholder="images/example.jpg" value="<?= htmlspecialchars($_POST['image'] ?? '', ENT_QUOTES, 'UTF-8') ?>">

    <button type="submit"><i class="fas fa-plus-circle"></i> Add Product</button>
    <a href="admin_products.php"><i class="fas fa-chevron-left"></i> Cancel</a>
  </form>
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
