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
        'file'  => $e->getFile(),
        'line'  => $e->getLine(),
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

/* ---------- CSRF token for forms ---------- */
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf = $_SESSION['csrf_token'];

/* ---------- DB ---------- */
require 'config.php'; // exposes $conn (MySQLi)
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT); // throw exceptions

/* ---------- Cart session ---------- */
if (!isset($_SESSION['cart'])) {
    $_SESSION['cart'] = [];
}

/* ---------- Helpers ---------- */
function require_csrf_or_die() {
    if (!hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token'] ?? '')) {
        app_log('csrf', 'CSRF token mismatch on cart action');
        http_response_code(400);
        exit('Invalid request.');
    }
}
function redirect_self() {
    header('Location: cart.php', true, 303);
    exit;
}

/* ================== Handle POST actions (with CSRF) ================== */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // All POSTs must include CSRF
    require_csrf_or_die();

    // ADD TO CART (can come from other pages posting to cart.php)
    if (isset($_POST['add_to_cart'])) {
        $id       = (int)($_POST['product_id'] ?? 0);
        $quantity = max(1, (int)($_POST['quantity'] ?? 1));
        if ($id > 0) {
            $_SESSION['cart'][$id] = ($_SESSION['cart'][$id] ?? 0) + $quantity;
        }
        redirect_self(); // PRG
    }

    // UPDATE CART (quantities)
    if (isset($_POST['update_cart'])) {
        if (isset($_POST['qty']) && is_array($_POST['qty'])) {
            foreach ($_POST['qty'] as $id => $qty) {
                $pid = (int)$id;
                $q   = max(0, (int)$qty);
                if ($pid <= 0) { continue; }
                if ($q > 0) {
                    $_SESSION['cart'][$pid] = $q;
                } else {
                    unset($_SESSION['cart'][$pid]);
                }
            }
        }
        redirect_self(); // PRG
    }

    // REMOVE ONE ITEM
    if (isset($_POST['remove_item'])) {
        $removeId = (int)($_POST['product_id'] ?? 0);
        if ($removeId > 0) {
            unset($_SESSION['cart'][$removeId]);
        }
        redirect_self(); // PRG
    }
}

/* ================== Build view model (safe DB access) ================== */
$cartItems = [];
$total = 0.0;

try {
    if (!empty($_SESSION['cart'])) {
        $ids = array_keys($_SESSION['cart']);
        // Build dynamic placeholders: ?, ?, ?, ...
        $placeholders = implode(',', array_fill(0, count($ids), '?'));
        $types = str_repeat('i', count($ids));

        $sql = "SELECT product_id, name, price FROM products WHERE product_id IN ($placeholders)";
        $stmt = $conn->prepare($sql);

        // bind_param needs references
        $params = [];
        $params[] = & $types;
        foreach ($ids as $k => $v) {
            $ids[$k] = (int)$v;
            $params[] = & $ids[$k];
        }
        call_user_func_array([$stmt, 'bind_param'], $params);

        $stmt->execute();
        $res = $stmt->get_result();

        while ($row = $res->fetch_assoc()) {
            $pid = (int)$row['product_id'];
            $qty = (int)($_SESSION['cart'][$pid] ?? 0);
            if ($qty <= 0) { continue; }
            $row['quantity'] = $qty;
            $row['subtotal'] = (float)$row['price'] * $qty;
            $total += $row['subtotal'];
            $cartItems[] = $row;
        }
        if ($res) { $res->free(); }
        $stmt->close();
    }
} catch (mysqli_sql_exception $e) {
    app_log('db_cart_error', 'Failed to load cart items', ['error' => $e->getMessage()]);
    // Leave $cartItems empty; show friendly UI below
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Your Cart</title>
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <link rel="stylesheet" href="index.css">
    <link rel="stylesheet" href="fontawesome-free-7.0.0-web/css/all.min.css">
    <style>
        .cart-container { max-width: 1000px; margin: auto; padding: 20px; }
        .cart-title { text-align: center; margin-bottom: 20px; }
        .cart-table { width: 100%; border-collapse: collapse; background: #1e1e1e; color: #fff; border-radius: 8px; overflow: hidden; }
        .cart-table th, .cart-table td { padding: 12px; text-align: center; border-bottom: 1px solid #333; }
        .cart-table th { background: #2d89ef; }
        .cart-table tr:last-child td { border-bottom: none; }
        .cart-actions { margin-top: 15px; text-align: right; }
        .btn { padding: 8px 15px; background: #2d89ef; color: white; border: none; border-radius: 4px; cursor: pointer; margin: 3px; text-decoration: none; display: inline-block; }
        .btn:hover { background: #1a5fbe; }
        input[type="number"] { width: 60px; padding: 5px; text-align: center; border-radius: 4px; border: 1px solid #ccc; }
        .remove-btn { color: #ff4d4d; text-decoration: none; background: none; border: none; cursor: pointer; }
        .remove-btn:hover { color: #ff1a1a; }
        .empty-cart { text-align: center; margin-top: 40px; }
        .empty-cart a { color: #2d89ef; text-decoration: none; }
        .empty-cart a:hover { text-decoration: underline; }
        .header-links { display:flex; gap:12px; align-items:center; }
    </style>
</head>
<body>

<header>
    <a href="index.php"><img src="images/logo.png" id="logo" alt="Logo"></a>
    <div class="user-links header-links">
        <a id="darkModeToggle" title="Toggle dark mode">🌙 Mood</a>
        <a href="index.php"><i class="fas fa-home"></i> Continue Shopping</a>
        <a href="logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a>
    </div>
</header>

<div class="cart-container">
    <h2 class="cart-title"><i class="fas fa-shopping-cart"></i> Your Shopping Cart</h2>

    <?php if (empty($cartItems)): ?>
        <div class="empty-cart">
            <p>Your cart is empty.</p>
            <a href="index.php">Go back and shop now</a>
        </div>
    <?php else: ?>
        <form method="post" action="cart.php">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
            <table class="cart-table">
                <tr>
                    <th>Product</th>
                    <th>Price (€)</th>
                    <th>Quantity</th>
                    <th>Subtotal (€)</th>
                    <th>Action</th>
                </tr>
                <?php foreach ($cartItems as $item): ?>
                <tr>
                    <td><?= htmlspecialchars($item['name'], ENT_QUOTES, 'UTF-8') ?></td>
                    <td><?= number_format((float)$item['price'], 2) ?></td>
                    <td>
                        <input type="number" name="qty[<?= (int)$item['product_id'] ?>]" 
                               value="<?= (int)$item['quantity'] ?>" min="0">
                    </td>
                    <td><?= number_format((float)$item['subtotal'], 2) ?></td>
                    <td>
                        <form method="post" action="cart.php" onsubmit="return confirm('Remove item?');" style="display:inline;">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
                            <input type="hidden" name="product_id" value="<?= (int)$item['product_id'] ?>">
                            <input type="hidden" name="remove_item" value="1">
                            <button type="submit" class="remove-btn" aria-label="Remove">
                               <i class="fas fa-trash-alt"></i>
                            </button>
                        </form>
                    </td>
                </tr>
                <?php endforeach; ?>
                <tr>
                    <td colspan="3"><strong>Total</strong></td>
                    <td colspan="2"><strong><?= number_format((float)$total, 2) ?></strong></td>
                </tr>
            </table>

            <div class="cart-actions">
                <button type="submit" name="update_cart" class="btn"><i class="fas fa-sync-alt"></i> Update Cart</button>
                <a href="checkout.php" class="btn"><i class="fas fa-credit-card"></i> Proceed to Checkout</a>
            </div>
        </form>
    <?php endif; ?>
</div>

<script>
const toggle = document.getElementById('darkModeToggle');
// Restore dark mode preference
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
