<?php
// search_ajax.php
$host = 'localhost';
$db   = 'webshop';
$user = 'Webuser';
$pass = 'Lab2024';

$conn = new mysqli($host, $user, $pass, $db);
if ($conn->connect_error) {
    http_response_code(500);
    exit("DB error");
}
$conn->set_charset("utf8mb4");

$keyword  = isset($_POST['keyword']) ? trim($_POST['keyword']) : '';
$category = isset($_POST['category']) ? trim($_POST['category']) : '';

// If keyword is empty, return no content so nothing renders
if ($keyword === '') {
    http_response_code(204); // No Content
    exit;
}

$sql = "SELECT p.*, c.name AS category_name
        FROM products p
        JOIN categories c ON p.category_id = c.category_id
        WHERE p.active = 1
          AND p.name LIKE CONCAT('%', ?, '%')";

if ($category !== '') {
    $sql .= " AND c.name = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ss", $keyword, $category);
} else {
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $keyword);
}

$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    echo "<p>No products found.</p>";     //send 200
} else {  // send 200
    while ($row = $result->fetch_assoc()) {
        echo "<div class='product-card'>";
        echo "<img src='".htmlspecialchars($row['image'])."' alt='".htmlspecialchars($row['name'])."'>";
        echo "<h3>".htmlspecialchars($row['name'])."</h3>";
        echo "<p>".htmlspecialchars($row['category_name'])."</p>";
        echo "<p>€".number_format($row['price'], 2)."</p>";
        echo "<a href='product.php?id=".$row['product_id']."'>View</a>";
        echo "</div>";
    }
}
$stmt->close();
$conn->close();
