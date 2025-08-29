<?php
// config.php 

$host = 'localhost';
$db   = 'webshop';
$user = 'Webuser';
$pass = 'Lab2024';

// Create connection
$conn = new mysqli($host, $user, $pass, $db);

// Check connection
if ($conn->connect_error) {
    error_log("Database connection failed: " . $conn->connect_error, 3, "log.txt");
    die("Database error. Try again later.");
}

// Set charset to utf8mb4
if (!$conn->set_charset("utf8mb4")) {
    error_log("Error loading character set utf8mb4: " . $conn->error, 3, "log.txt");
    die("Database charset error.");
}
?>
