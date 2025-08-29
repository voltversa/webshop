<?php
session_start();
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}
echo "Welcome, " . htmlspecialchars($_SESSION['email']) . "!";
echo "<br><a href='logout.php'>Logout</a>";
?>
