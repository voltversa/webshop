CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role ENUM('normal', 'admin') DEFAULT 'normal',
    contact VARCHAR(50),
    active BOOLEAN DEFAULT TRUE,
    address VARCHAR(255),
    street VARCHAR(100),
    street_number VARCHAR(10),
    postal_code VARCHAR(10),
    country VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE shippers (
    shipper_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100),
    contact VARCHAR(50),
    active BOOLEAN DEFAULT TRUE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE categories (
    category_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE products (
    product_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price DECIMAL(10, 2) NOT NULL,
    image VARCHAR(255),
    category_id INT,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (category_id) REFERENCES categories(category_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE orders (
    order_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    shipper_id INT,
    date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    paid BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (shipper_id) REFERENCES shippers(shipper_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE order_items (
    order_item_id INT AUTO_INCREMENT PRIMARY KEY,
    order_id INT NOT NULL,
    product_id INT NOT NULL,
    quantity INT NOT NULL,
    FOREIGN KEY (order_id) REFERENCES orders(order_id),
    FOREIGN KEY (product_id) REFERENCES products(product_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE reviews (
    review_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    product_id INT NOT NULL,
    text TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (product_id) REFERENCES products(product_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

----
INSERT INTO categories (name) VALUES 
('Pets'),
('Clothing'),
('Electronics'),
('Gifts'),
('Best Sellers');

INSERT INTO products (name, description, price, image, category_id) VALUES
('Men T-Shirt', 'Comfortable cotton t-shirt for men.', 19.99, 'images/tshirt.jpg', 1),
('Laptop', '14-inch powerful laptop for all your needs.', 599.00, 'images/laptop.jpg', 2),
('Gift Box', 'Perfect gift box for any occasion.', 24.50, 'images/giftbox.jpg', 3),
('Wireless Headphones', 'High-quality Bluetooth headphones.', 89.90, 'images/headphones.jpg', 2),
('Women Dress', 'Elegant dress suitable for parties.', 39.99, 'images/dress.jpg', 1);
----------------------------------------------------------------------------------------------------
INSERT INTO products (name, description, price, image, category_id) VALUES
('Casual Hoodie', 'Unisex hoodie made from soft fleece.', 29.99, 'images/hoodie.jpg', 1),
('Women Jeans', 'Skinny fit jeans for women.', 34.99, 'images/jeans.jpg', 1),
('Kids Sweater', 'Warm wool sweater for kids.', 19.50, 'images/kids_sweater.jpg', 1);
----------------------------------------------------------------------------------------------------

INSERT INTO products (name, description, price, image, category_id) VALUES
('Smartphone', 'Latest 5G Android smartphone.', 749.00, 'images/smartphone.jpg', 2),
('Smart Watch', 'Track your fitness and notifications.', 129.99, 'images/smartwatch.jpg', 2),
('Bluetooth Speaker', 'Portable speaker with deep bass.', 45.00, 'images/speaker.jpg', 2);
----------------------------------------------------------------------------------------------------

INSERT INTO products (name, description, price, image, category_id) VALUES
('Custom Mug', 'Personalized ceramic mug.', 12.50, 'images/mug.jpg', 3),
('Photo Frame', 'Wooden photo frame 8x10 inches.', 14.00, 'images/photo_frame.jpg', 3),
('Candle Set', 'Scented candles set of 3.', 18.75, 'images/candle_set.jpg', 3);
----------------------------------------------------------------------------------------------------

INSERT INTO products (name, description, price, image, category_id) VALUES
('Wireless Mouse', 'Ergonomic mouse for laptops.', 15.00, 'images/mouse.jpg', 4),
('Graphic T-Shirt', 'Trending t-shirt with unique design.', 22.00, 'images/graphic_tee.jpg', 4),
('Mini Backpack', 'Stylish compact backpack.', 28.99, 'images/backpack.jpg', 4);
----------------------------------------------------------------------------------------------------

INSERT INTO shippers (name, email, contact) VALUES
('BPost', 'contact@bpost.be', '+32 2 123 4567'),
('DHL', 'support@dhl.com', '+49 221 123456'),
('DPD', 'service@dpd.com', '+49 1806 373 200'),
('PostNL', 'info@postnl.nl', '+31 88 868 6161');
