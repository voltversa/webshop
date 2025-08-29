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
// Optional CSP (enable after auditing assets):
// header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; font-src 'self'; frame-ancestors 'self';");

/* ---------- CSRF token for forms ---------- */
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf = $_SESSION['csrf_token'];

/* ================== Requirements & DB ================== */
require 'config.php'; // MySQLi $conn
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT); // throw exceptions

// Require login
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}
$user_id = (int)$_SESSION['user_id'];

// Ensure cart exists and not empty
if (empty($_SESSION['cart']) || !is_array($_SESSION['cart'])) {
    header("Location: cart.php");
    exit;
}

/* ================== Prefill user info ================== */
$user = [];
try {
    $stmt = $conn->prepare("
        SELECT first_name, last_name, email, contact, address, street, street_number, postal_code, country
        FROM users WHERE user_id = ?
    ");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc() ?: [];
    if ($result) $result->free();
    $stmt->close();
} catch (mysqli_sql_exception $e) {
    app_log('db_checkout_user', 'Failed to load user info', ['error' => $e->getMessage(), 'user_id' => $user_id]);
}

/* ================== Build cart summary (safe IN) ================== */
$cartItems = [];
$cartTotal = 0.0;

try {
    $ids = array_keys($_SESSION['cart']);          
    if (empty($ids)) {
        header("Location: cart.php");
        exit;
    }
    // Build dynamic placeholders (?, ?, ...)
    $placeholders = implode(',', array_fill(0, count($ids), '?')); 
    $types = str_repeat('i', count($ids));

    $sql = "SELECT product_id, name, price, image FROM products WHERE product_id IN ($placeholders)";
    $stmt = $conn->prepare($sql);

    // bind_param requires references
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
        $cartTotal += $row['subtotal'];
        $cartItems[] = $row;
    }
    if ($res) $res->free();
    $stmt->close();
} catch (mysqli_sql_exception $e) {
    app_log('db_checkout_cart', 'Failed to load cart products', ['error' => $e->getMessage()]);
}

/* ================== Load active shippers ================== */
$shippers = [];
try {
    $resShip = $conn->query("SELECT shipper_id, name FROM shippers WHERE active = 1 ORDER BY name");
    while ($s = $resShip->fetch_assoc()) { $shippers[] = $s; }
    $resShip->free();
} catch (mysqli_sql_exception $e) {
    app_log('db_checkout_shippers', 'Failed to load shippers', ['error' => $e->getMessage()]);
}

/* ================== Handle order submission (POST) ================== */
$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['place_order'])) {
    // CSRF check
    $token = isset($_POST['csrf_token']) ? $_POST['csrf_token'] : '';
    if (!hash_equals($_SESSION['csrf_token'], $token)) {
        app_log('csrf', 'CSRF token mismatch on checkout', ['user_id' => $user_id]);
        http_response_code(400);
        $errors[] = 'Invalid request.';
    } else {
        // Collect + normalize inputs
        $first_name   = isset($_POST['first_name'])   ? trim($_POST['first_name'])   : '';
        $last_name    = isset($_POST['last_name'])    ? trim($_POST['last_name'])    : '';
        $email        = isset($_POST['email'])        ? trim($_POST['email'])        : '';
        $contact      = isset($_POST['contact'])      ? trim($_POST['contact'])      : '';
        $address      = isset($_POST['address'])      ? trim($_POST['address'])      : '';
        $street       = isset($_POST['street'])       ? trim($_POST['street'])       : '';
        $street_no    = isset($_POST['street_number'])? trim($_POST['street_number']) : '';
        $postal_code  = isset($_POST['postal_code'])  ? trim($_POST['postal_code'])  : '';
        $country      = isset($_POST['country'])      ? trim($_POST['country'])      : '';
        $shipper_id   = (int)($_POST['shipper_id'] ?? 0);

        // Basic validation
        if ($first_name === '' || $last_name === '') $errors[] = "First name and last name are required.";
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = "A valid email is required.";
        if ($shipper_id <= 0) $errors[] = "Please choose a shipper.";
        if (empty($cartItems)) $errors[] = "Your cart is empty.";

        // Ensure shipper exists and active
        if ($shipper_id > 0) {
            try {
                $chk = $conn->prepare("SELECT shipper_id FROM shippers WHERE shipper_id = ? AND active = 1");
                $chk->bind_param("i", $shipper_id);
                $chk->execute();
                $r = $chk->get_result();
                if (!$r->fetch_assoc()) { $errors[] = "Selected shipper is not available."; }
                if ($r) $r->free();
                $chk->close();
            } catch (mysqli_sql_exception $e) {
                app_log('db_checkout_shipper_check', 'Failed to validate shipper', ['error' => $e->getMessage(), 'shipper_id' => $shipper_id]);
                $errors[] = "Unable to validate shipper. Please try again.";
            }
            }

        // Create order if no errors
        if (empty($errors)) {
            try {
                $conn->begin_transaction(); // 5

                // Update user info 
                $up = $conn->prepare("
                    UPDATE users SET first_name=?, last_name=?, email=?, contact=?, address=?, street=?, street_number=?, postal_code=?, country=?
                    WHERE user_id=?
                ");
                $up->bind_param("sssssssssi",
                    $first_name, $last_name, $email, $contact, $address, $street, $street_no, $postal_code, $country, $user_id
                );
                $up->execute();
                $up->close();

                // Insert order
                $ord = $conn->prepare("INSERT INTO orders (user_id, shipper_id, paid) VALUES (?, ?, 0)");
                $ord->bind_param("ii", $user_id, $shipper_id);
                $ord->execute();
                $order_id = $ord->insert_id;
                $ord->close();

                // Insert order items
                $itm = $conn->prepare("INSERT INTO order_items (order_id, product_id, quantity) VALUES (?, ?, ?)");
                foreach ($cartItems as $ci) {
                    $pid = (int)$ci['product_id'];
                    $q   = (int)$ci['quantity'];
                    if ($q > 0) {
                        $itm->bind_param("iii", $order_id, $pid, $q);
                        $itm->execute();
                    }
                }
                $itm->close();

                $conn->commit();

                // Clear cart and redirect (PRG)
                $_SESSION['cart'] = [];
                header("Location: order_success.php?order_id=" . (int)$order_id);
                exit;
            } catch (Throwable $e) {
                $conn->rollback();
                app_log('db_checkout_order', 'Order transaction failed', ['error' => $e->getMessage(), 'user_id' => $user_id]);
                $errors[] = "Order failed. Please try again.";
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Checkout</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link rel="stylesheet" href="index.css">
  <link rel="stylesheet" href="fontawesome-free-7.0.0-web/css/all.min.css">
  <style>
    .checkout-container { max-width: 1100px; margin: 20px auto; padding: 20px; }
    .grid { display: grid; grid-template-columns: 2fr 1fr; gap: 20px; }
    .panel { background: var(--header-bg); border: 1px solid #ddd; border-radius: 8px; padding: 16px; box-shadow: 0 2px 4px var(--shadow); }
    .panel h3 { margin-top: 0; }
    .cart-table { width: 100%; border-collapse: collapse; }
    .cart-table th, .cart-table td { padding: 10px; border-bottom: 1px solid #ddd; text-align: left; }
    .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
    .form-row.full { grid-template-columns: 1fr; }
    .form-row label { display:block; margin: 8px 0 4px; }
    .form-row input, .form-row select { width: 100%; padding: 10px; border-radius: 6px; border: 1px solid #ccc; }
    .total-line { display:flex; justify-content: space-between; font-weight: bold; padding-top: 10px; }
    .btn { display:inline-block; background: var(--button-bg); color:#fff; border:none; padding:10px 16px; border-radius:6px; cursor:pointer; text-decoration:none; }
    .btn:hover { background: var(--button-hover); }
    .error { background:#fdecea; color:#b71c1c; border:1px solid #f5c2c7; padding:10px; border-radius:6px; margin-bottom:10px; }
    /* Dark mode tweaks */
    body.dark .panel { background: var(--nav-bg); border: 1px solid #444; }
    body.dark .cart-table th, body.dark .cart-table td { border-color:#444; }
    body.dark .form-row input, body.dark .form-row select { background:#1e1e1e; color:var(--text-color); border-color:#444; }
  </style>
</head>
<body>

<header>
  <a href="index.php"><img src="images/logo.png" id="logo" alt="Logo"></a>
  <div class="user-links">
    <a href="cart.php"><i class="fas fa-shopping-cart"></i> Cart</a>
    <a id="darkModeToggle" title="Toggle dark mode">🌙 Mood</a>
    <a href="logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a>
  </div>
</header>

<div class="checkout-container">
  <?php if (!empty($errors)): ?>
    <div class="error">
      <?php foreach ($errors as $e) echo "<div>".htmlspecialchars($e, ENT_QUOTES, 'UTF-8')."</div>"; ?>
    </div>
  <?php endif; ?>

  <div class="grid">
    <!-- Left: Order Summary -->
    <div class="panel">
      <h3>Order Summary</h3>
      <?php if (empty($cartItems)): ?>
        <p>Your cart is empty.</p>
      <?php else: ?>
        <table class="cart-table">
          <tr><th>Product</th><th>Qty</th><th>Price</th><th>Subtotal</th></tr>
          <?php foreach ($cartItems as $ci): ?>
          <tr>
            <td><?= htmlspecialchars($ci['name'], ENT_QUOTES, 'UTF-8') ?></td>
            <td><?= (int)$ci['quantity'] ?></td>
            <td>€<?= number_format((float)$ci['price'], 2) ?></td>
            <td>€<?= number_format((float)$ci['subtotal'], 2) ?></td>
          </tr>
          <?php endforeach; ?>
        </table>
        <div class="total-line">
          <div>Total</div>
          <div>€<?= number_format((float)$cartTotal, 2) ?></div>
        </div>
      <?php endif; ?>
    </div>

    <!-- Right: Shipping, Address, Place Order -->
    <div class="panel">
      <h3>Shipping & Address</h3>
      <form method="post" novalidate>
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
        <div class="form-row">
          <div>
            <label>First Name</label>
            <input type="text" name="first_name" value="<?= htmlspecialchars($user['first_name'] ?? '', ENT_QUOTES, 'UTF-8') ?>" required>
          </div>
          <div>
            <label>Last Name</label>
            <input type="text" name="last_name" value="<?= htmlspecialchars($user['last_name'] ?? '', ENT_QUOTES, 'UTF-8') ?>" required>
          </div>
        </div>

        <div class="form-row">
          <div>
            <label>Email</label>
            <input type="email" name="email" value="<?= htmlspecialchars($user['email'] ?? '', ENT_QUOTES, 'UTF-8') ?>" required>
          </div>
          <div>
            <label>Contact</label>
            <input type="text" name="contact" value="<?= htmlspecialchars($user['contact'] ?? '', ENT_QUOTES, 'UTF-8') ?>">
          </div>
        </div>

        <div class="form-row full">
          <div>
            <label>Address</label>
            <input type="text" name="address" value="<?= htmlspecialchars($user['address'] ?? '', ENT_QUOTES, 'UTF-8') ?>">
          </div>
        </div>

        <div class="form-row">
          <div>
            <label>Street</label>
            <input type="text" name="street" value="<?= htmlspecialchars($user['street'] ?? '', ENT_QUOTES, 'UTF-8') ?>">
          </div>
          <div>
            <label>Street No.</label>
            <input type="text" name="street_number" value="<?= htmlspecialchars($user['street_number'] ?? '', ENT_QUOTES, 'UTF-8') ?>">
          </div>
        </div>

        <div class="form-row">
          <div>
            <label>Postal Code</label>
            <input type="text" name="postal_code" value="<?= htmlspecialchars($user['postal_code'] ?? '', ENT_QUOTES, 'UTF-8') ?>">
          </div>
          <div>
            <label>Country</label>
            <input type="text" name="country" value="<?= htmlspecialchars($user['country'] ?? '', ENT_QUOTES, 'UTF-8') ?>">
          </div>
        </div>

        <div class="form-row full">
          <div>
            <label>Choose Shipper</label>
            <select name="shipper_id" required>
              <option value="">-- Select --</option>
              <?php foreach ($shippers as $s): ?>
                <option value="<?= (int)$s['shipper_id'] ?>"><?= htmlspecialchars($s['name'], ENT_QUOTES, 'UTF-8') ?></option>
              <?php endforeach; ?>
            </select>
          </div>
        </div>

        <div style="margin-top:12px; text-align:right;">
          <button class="btn" type="submit" name="place_order"><i class="fas fa-check"></i> Place Order</button>
        </div>
      </form>
    </div>
  </div>
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
