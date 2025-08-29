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
    if (!(error_reporting() & $severity)) { return false; } // respect @
    app_log('php_error', $message, ['file'=>$file,'line'=>$line,'severity'=>$severity]);
    throw new ErrorException($message, 0, $severity, $file, $line);
});
set_exception_handler(function ($e) {
    app_log('exception', $e->getMessage(), [
        'file'  => $e->getFile(), 'line' => $e->getLine(),
        'trace' => array_slice(explode("\n", $e->getTraceAsString()), 0, 20),
        'user'  => $_SESSION['user_id'] ?? null,
    ]);
    http_response_code(500);
    if (!headers_sent()) header('Content-Type: text/html; charset=utf-8');
    echo '<h1>Something went wrong</h1><p>Please try again later.</p>';
    exit;
});
register_shutdown_function(function () {
    $e = error_get_last();
    if ($e && in_array($e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
        app_log('fatal', $e['message'], ['file'=>$e['file'], 'line'=>$e['line']]);
        http_response_code(500);
        if (!headers_sent()) header('Content-Type: text/html; charset=utf-8');
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

/* ================== Page logic ================== */
require 'config.php'; // provides $conn (MySQLi)
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT); // throw exceptions

// Require a valid order_id
$order_id = isset($_GET['order_id']) ? (int)$_GET['order_id'] : 0;
if ($order_id <= 0) {
    app_log('order_success_bad_id', 'Missing/invalid order_id', ['order_id' => $_GET['order_id'] ?? null]);
    header("Location: index.php");
    exit;
}

// Require login to view success (and verify ownership)
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}
$user_id = (int)$_SESSION['user_id'];

// Verify the order belongs to the logged-in user
try {
    $stmt = $conn->prepare("SELECT 1 FROM orders WHERE order_id = ? AND user_id = ?");
    $stmt->bind_param("ii", $order_id, $user_id);
    $stmt->execute();
    $res = $stmt->get_result();
    $ok = (bool)($res && $res->fetch_row());
    if ($res) $res->free();
    $stmt->close();

    if (!$ok) {
        app_log('order_success_forbidden', 'Order does not belong to user', ['order_id' => $order_id, 'user_id' => $user_id]);
        header("Location: index.php");
        exit;
    }
} catch (mysqli_sql_exception $e) {
    app_log('order_success_check_failed', 'Failed to verify order ownership', ['error' => $e->getMessage(), 'order_id' => $order_id, 'user_id' => $user_id]);
    // Fail safely: hide details from user
    header("Location: index.php");
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Order Success</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link rel="stylesheet" href="index.css">
  <link rel="stylesheet" href="fontawesome-free-7.0.0-web/css/all.min.css">
  <style>
    .success-wrap { max-width: 800px; margin: 40px auto; background: var(--header-bg); padding: 30px; border-radius: 10px; border: 1px solid #ddd; text-align: center; box-shadow: 0 2px 4px var(--shadow); }
    .success-wrap h2 { margin-top: 0; }
    .btn { display:inline-block; margin-top:15px; background: var(--button-bg); color:#fff; padding:10px 16px; border-radius:6px; text-decoration:none; }
    .btn:hover { background: var(--button-hover); }
    body.dark .success-wrap { background: var(--nav-bg); border: 1px solid #444; }
    .header-links { display:flex; gap:12px; align-items:center; }
  </style>
</head>
<body>
<header>
  <a href="index.php"><img src="images/logo.png" id="logo" alt="Logo"></a>
  <div class="user-links header-links">
    <a id="darkModeToggle" title="Toggle dark mode">🌙 Mood</a>
    <a href="index.php"><i class="fas fa-home"></i> Home</a>
    <a href="logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a>
  </div>
</header>

<div class="success-wrap">
  <h2>✅ Thank you! Your order has been placed.</h2>
  <p>Your order number is <strong>#<?= htmlspecialchars((string)$order_id, ENT_QUOTES, 'UTF-8') ?></strong>.</p>
  <a class="btn" href="index.php">Continue Shopping</a>
  <a class="btn" href="orders.php">View My Orders</a>
</div>

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
