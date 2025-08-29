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
// Optional CSP after auditing assets:
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
        app_log('csrf', 'CSRF token mismatch on admin_users action');
        http_response_code(400);
        exit('Invalid request.');
    }
}

/* ================== Handle POST actions ================== */
$flash = ''; // optional message banner

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_csrf_or_400();
    try {
        // Normalize shared fields
        $userId = isset($_POST['user_id']) ? (int)$_POST['user_id'] : 0;

        // Prevent self-demotion lockout (optional safeguard)
        $currentUserId = (int)($_SESSION['user_id'] ?? 0);

        // Toggle role
        if (isset($_POST['toggle_role']) && $userId > 0) {
            // If toggling our own role from admin->normal, allow only if there is another admin (optional rule).
            if ($userId === $currentUserId) {
                // Count other admins
                $rs = $conn->query("SELECT COUNT(*) AS c FROM users WHERE role='admin' AND user_id <> ".(int)$currentUserId);
                $row = $rs->fetch_assoc(); $rs->free();
                if ((int)$row['c'] === 0) {
                    $flash = 'Cannot remove your own admin role: at least one other admin is required.';
                    redirect_self();
                }
            }
            $stmt = $conn->prepare("UPDATE users SET role = IF(role = 'admin', 'normal', 'admin') WHERE user_id = ?");
            $stmt->bind_param("i", $userId);
            $stmt->execute();
            $stmt->close();
            $flash = 'Role updated.';
        }

        // Activate/Deactivate
        if (isset($_POST['toggle_active']) && $userId > 0) {
            // Avoid deactivating yourself (optional safety)
            if ($userId === $currentUserId) {
                $flash = 'You cannot deactivate your own account.';
                redirect_self();
            }
            $stmt = $conn->prepare("UPDATE users SET active = NOT active WHERE user_id = ?");
            $stmt->bind_param("i", $userId);
            $stmt->execute();
            $stmt->close();
            $flash = 'User status updated.';
        }

        // Edit user data
        if (isset($_POST['edit_user']) && $userId > 0) {
            $email      = isset($_POST['email']) ? trim($_POST['email']) : '';
            $first_name = isset($_POST['first_name']) ? trim($_POST['first_name']) : '';
            $last_name  = isset($_POST['last_name']) ? trim($_POST['last_name']) : '';
            $role       = isset($_POST['role']) ? $_POST['role'] : 'normal';
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $flash = 'Invalid email format.'; redirect_self();
            }
            if (!in_array($role, ['normal','admin'], true)) {
                $flash = 'Invalid role.'; redirect_self();
            }
            // Avoid demoting last admin (optional)
            if ($userId === $currentUserId && $role !== 'admin') {
                $rs = $conn->query("SELECT COUNT(*) AS c FROM users WHERE role='admin' AND user_id <> ".(int)$currentUserId);
                $row = $rs->fetch_assoc(); $rs->free();
                if ((int)$row['c'] === 0) {
                    $flash = 'At least one admin must remain.'; redirect_self();
                }
            }
            // Unique email check
            $chk = $conn->prepare("SELECT 1 FROM users WHERE email = ? AND user_id <> ? LIMIT 1");
            $chk->bind_param("si", $email, $userId);
            $chk->execute();
            $dup = $chk->get_result()->fetch_row();
            $chk->close();
            if ($dup) { $flash = 'Email already in use.'; redirect_self(); }

            $stmt = $conn->prepare("UPDATE users SET email=?, first_name=?, last_name=?, role=? WHERE user_id = ?");
            $stmt->bind_param("ssssi", $email, $first_name, $last_name, $role, $userId);
            $stmt->execute();
            $stmt->close();
            $flash = 'User updated.';
        }

        // Add new user
        if (isset($_POST['add_user'])) {
            $email      = isset($_POST['email']) ? trim($_POST['email']) : '';
            $password   = $_POST['password'] ?? '';
            $first_name = isset($_POST['first_name']) ? trim($_POST['first_name']) : '';
            $last_name  = isset($_POST['last_name']) ? trim($_POST['last_name']) : '';
            $role       = isset($_POST['role']) ? $_POST['role'] : 'normal';

            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) { $flash = 'Invalid email format.'; redirect_self(); }
            if (strlen($password) < 6) { $flash = 'Password must be at least 6 characters.'; redirect_self(); }
            if (!in_array($role, ['normal','admin'], true)) { $flash = 'Invalid role.'; redirect_self(); }

            // Unique email
            $chk = $conn->prepare("SELECT 1 FROM users WHERE email = ? LIMIT 1");
            $chk->bind_param("s", $email);
            $chk->execute();
            $dup = $chk->get_result()->fetch_row();
            $chk->close();
            if ($dup) { $flash = 'Email already registered.'; redirect_self(); }

            $hash = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $conn->prepare("INSERT INTO users (email, password, first_name, last_name, role, active) VALUES (?, ?, ?, ?, ?, 1)");
            $stmt->bind_param("sssss", $email, $hash, $first_name, $last_name, $role);
            $stmt->execute();
            $stmt->close();
            $flash = 'User added.';
        }
    } catch (Throwable $e) {
        app_log('admin_users_post_error', 'Action failed', ['error'=>$e->getMessage()]);
        $flash = 'Operation failed. Please try again.';
    }
    // PRG
    $_SESSION['flash'] = $flash;
    redirect_self();
}

/* ================== Fetch users ================== */
$users = [];
try {
    $result = $conn->query("SELECT user_id, email, first_name, last_name, role, active, created_at FROM users ORDER BY created_at DESC");
    while ($row = $result->fetch_assoc()) { $users[] = $row; }
    $result->free();
} catch (mysqli_sql_exception $e) {
    app_log('admin_users_fetch_error', 'Failed to load users', ['error'=>$e->getMessage()]);
}

/* Flash message */
if (isset($_SESSION['flash'])) { $flash = $_SESSION['flash']; unset($_SESSION['flash']); } else { $flash = ''; }
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>User Management</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link rel="stylesheet" href="index.css">
  <link rel="stylesheet" href="fontawesome-free-7.0.0-web/css/all.min.css">
  <style>
    .admin-container { padding: 20px; max-width: 1000px; margin: auto; }
    .user-table { width: 100%; border-collapse: collapse; }
    .user-table th, .user-table td { padding: 10px; border: 1px solid #ccc; text-align: center; }
    .admin-container h2 { margin-bottom: 15px; }
    .add-form, .edit-form { display: none; background: var(--nav-bg); padding: 15px; border-radius: 8px; margin: 20px 0; }
    .btn { padding: 6px 12px; cursor: pointer; background: #2d89ef; color: white; border: none; border-radius: 4px; margin: 2px; }
    .btn:hover { background: #1a5fbe; }
    .add-form input, .add-form select, .edit-form input, .edit-form select { padding:8px; margin:6px 4px; border:1px solid #ccc; border-radius:4px; }
    .flash { margin:10px 0; padding:10px; border-radius:6px; background:#eef6ff; color:#0b4f8a; border:1px solid #b6daff; }
    body.dark .flash { background:#16324a; color:#e6f1ff; border-color:#204a6b; }
  </style>
</head>
<body>

<header>
  <a href="index.php"><img src="images/logo.png" id="logo" alt="Logo"></a>
  <div class="user-links">
    <a href="admin_dashboard.php"><i class="fas fa-arrow-left"></i> Back to Dashboard</a>
    <a href="logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a>
    <a id="darkModeToggle" title="Toggle dark mode">🌙 Mood</a>
  </div>
</header>

<div class="admin-container">
  <h2>User Management</h2>

  <?php if ($flash): ?>
    <div class="flash"><?= htmlspecialchars($flash, ENT_QUOTES, 'UTF-8') ?></div>
  <?php endif; ?>

  <button class="btn" onclick="toggleForm('addForm')"><i class="fas fa-user-plus"></i> Add New User</button>

  <!-- Add User Form -->
  <form method="post" id="addForm" class="add-form" novalidate>
    <h3>Add New User</h3>
    <input type="hidden" name="add_user" value="1">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
    <input type="email" name="email" placeholder="Email" required>
    <input type="text" name="first_name" placeholder="First Name" required>
    <input type="text" name="last_name" placeholder="Last Name" required>
    <input type="password" name="password" placeholder="Password (min 6 chars)" required>
    <select name="role">
      <option value="normal">Normal</option>
      <option value="admin">Admin</option>
    </select>
    <button class="btn" type="submit">Add User</button>
  </form>

  <table class="user-table">
    <tr>
      <th>ID</th><th>Email</th><th>Name</th><th>Role</th><th>Status</th><th>Actions</th>
    </tr>
    <?php foreach ($users as $u): ?>
    <tr>
      <td><?= (int)$u['user_id'] ?></td>
      <td><?= htmlspecialchars($u['email'], ENT_QUOTES, 'UTF-8') ?></td>
      <td><?= htmlspecialchars($u['first_name'].' '.$u['last_name'], ENT_QUOTES, 'UTF-8') ?></td>
      <td><?= htmlspecialchars($u['role'], ENT_QUOTES, 'UTF-8') ?></td>
      <td><?= ((int)$u['active'] === 1) ? 'Active' : 'Inactive' ?></td>
      <td>
        <form method="post" style="display:inline;" onsubmit="return confirm('Toggle role for this user?');">
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
          <input type="hidden" name="user_id" value="<?= (int)$u['user_id'] ?>">
          <button class="btn" name="toggle_role">Toggle Role</button>
        </form>

        <form method="post" style="display:inline;" onsubmit="return confirm('Toggle active status?');">
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
          <input type="hidden" name="user_id" value="<?= (int)$u['user_id'] ?>">
          <button class="btn" name="toggle_active">Toggle Active</button>
        </form>

        <button class="btn" onclick="toggleEdit('edit<?= (int)$u['user_id'] ?>')">✏️ Edit</button>
        <form method="post" id="edit<?= (int)$u['user_id'] ?>" class="edit-form" novalidate>
          <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8') ?>">
          <input type="hidden" name="user_id" value="<?= (int)$u['user_id'] ?>">
          <input type="hidden" name="edit_user" value="1">
          <input type="email" name="email" value="<?= htmlspecialchars($u['email'], ENT_QUOTES, 'UTF-8') ?>" required>
          <input type="text" name="first_name" value="<?= htmlspecialchars($u['first_name'], ENT_QUOTES, 'UTF-8') ?>" required>
          <input type="text" name="last_name" value="<?= htmlspecialchars($u['last_name'], ENT_QUOTES, 'UTF-8') ?>" required>
          <select name="role">
            <option value="normal" <?= $u['role'] === 'normal' ? 'selected' : '' ?>>Normal</option>
            <option value="admin"  <?= $u['role'] === 'admin'  ? 'selected' : '' ?>>Admin</option>
          </select>
          <button class="btn" type="submit">Save</button>
        </form>
      </td>
    </tr>
    <?php endforeach; ?>
  </table>
</div>

<script>
  function toggleForm(id) {
    const el = document.getElementById(id);
    el.style.display = el.style.display === 'block' ? 'none' : 'block';
  }
  function toggleEdit(id) {
    const el = document.getElementById(id);
    el.style.display = el.style.display === 'block' ? 'none' : 'block';
  }
</script>
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
