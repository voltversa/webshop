<?php
session_start();
require 'config.php'; // $conn MySQLi connection

// Require login
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

$user_id = (int)$_SESSION['user_id'];

// Fetch all orders for the user
$stmt = $conn->prepare("
   SELECT o.order_id, o.paid, o.date, s.name AS shipper_name
    FROM orders o
    LEFT JOIN shippers s ON o.shipper_id = s.shipper_id
    WHERE o.user_id = ?
    ORDER BY o.date DESC
");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$orders_result = $stmt->get_result();
$orders = $orders_result->fetch_all(MYSQLI_ASSOC);
$stmt->close();

// Fetch all items for these orders in one query
$order_items = [];
if (!empty($orders)) {
    $ids = '';
    foreach ($orders as $o) {
        if ($ids !== '') { $ids .= ','; }
        $ids .= (int)$o['order_id'];
    }

    $sql = "
        SELECT oi.order_id, p.name, oi.quantity, p.price
        FROM order_items oi
        JOIN products p ON oi.product_id = p.product_id
        WHERE oi.order_id IN ($ids)
    ";
    $res_items = $conn->query($sql);
    while ($row = $res_items->fetch_assoc()) {
        $order_items[$row['order_id']][] = $row;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>My Orders</title>
    <link rel="stylesheet" href="index.css">
    <link rel="stylesheet" href="fontawesome-free-7.0.0-web/css/all.min.css">
    <style>
        .orders-container { max-width: 1000px; margin: 20px auto; padding: 20px; }
        .order-box { background: var(--header-bg); border: 1px solid #ddd; border-radius: 8px; margin-bottom: 20px; padding: 16px; box-shadow: 0 2px 4px var(--shadow); }
        .order-header { display: flex; justify-content: space-between; flex-wrap: wrap; margin-bottom: 10px; }
        .order-header div { margin-right: 15px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        table th, table td { padding: 8px; border-bottom: 1px solid #ddd; }
        .total-line { text-align: right; font-weight: bold; padding-top: 8px; }
        .status-paid { color: green; font-weight: bold; }
        .status-unpaid { color: red; font-weight: bold; }
        /* Dark mode tweaks */
        body.dark .order-box { background: var(--nav-bg); border-color: #444; }
        body.dark table th, body.dark table td { border-color: #444; }
    </style>
</head>
<body>

<header>
    <a href="index.php"><img src="images/logo.png" id="logo" alt="Logo"></a>
    <div class="user-links">
        <a href="cart.php"><i class="fas fa-shopping-cart"></i> Cart</a>
        <a href="orders.php"><i class="fas fa-box"></i> My Orders</a>
        <a id="darkModeToggle">🌙 Mood</a>
        <a href="logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a>
    </div>
</header>

<div class="orders-container">
    <h2>My Orders</h2>
    <?php if (empty($orders)): ?>
        <p>You haven't placed any orders yet.</p>
    <?php else: ?>
        <?php foreach ($orders as $order): ?>
            <div class="order-box">
                <div class="order-header">
                    <div><strong>Order #<?= $order['order_id'] ?></strong></div>
                   <div>Date: <?= htmlspecialchars($order['date']) ?></div>
                    <div>Shipper: <?= htmlspecialchars($order['shipper_name'] ?? 'N/A') ?></div>
                    <div>Status: 
                        <?php if ($order['paid']): ?>
                            <span class="status-paid">Paid</span>
                        <?php else: ?>
                            <span class="status-unpaid">Unpaid</span>
                        <?php endif; ?>
                    </div>
                </div>

                <?php if (!empty($order_items[$order['order_id']])): ?>
                    <table>
                        <tr>
                            <th>Product</th>
                            <th>Qty</th>
                            <th>Price</th>
                            <th>Subtotal</th>
                        </tr>
                        <?php 
                        $total = 0;
                        foreach ($order_items[$order['order_id']] as $item):
                            $subtotal = $item['price'] * $item['quantity'];
                            $total += $subtotal;
                        ?>
                            <tr>
                                <td><?= htmlspecialchars($item['name']) ?></td>
                                <td><?= (int)$item['quantity'] ?></td>
                                <td>€<?= number_format($item['price'], 2) ?></td>
                                <td>€<?= number_format($subtotal, 2) ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </table>
                    <div class="total-line">Total: €<?= number_format($total, 2) ?></div>
                <?php endif; ?>
            </div>
        <?php endforeach; ?>
    <?php endif; ?>
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
  
  if (document.body.classList.contains('dark')) {
    localStorage.setItem('theme', 'dark');
    toggle.textContent = '☀️ Mood';
  } else {
    localStorage.setItem('theme', 'light');
    toggle.textContent = '🌙 Mood';
  }
});
</script>

</body>
</html>
