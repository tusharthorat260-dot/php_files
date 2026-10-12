<?php
declare(strict_types=1);

session_start();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: signup.html');
    exit;
}

// Update these credentials for your MySQL server.
$host = 'localhost';
$dbname = 'fortune_cloud';
$username = 'root';
$dbpassword = '';

try {
    $pdo = new PDO(
        "mysql:host=$host;dbname=$dbname;charset=utf8mb4",
        $username,
        $dbpassword,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false
        ]
    );
} catch (PDOException $e) {
    error_log($e->getMessage());
    http_response_code(500);
    exit('Database connection failed. Please try again later.');
}

$name = trim($_POST['name'] ?? '');
$email = trim($_POST['email'] ?? '');
$phone = trim($_POST['phone'] ?? '');
$password = $_POST['password'] ?? '';
$confirm = $_POST['confirm_password'] ?? '';
$terms = $_POST['terms'] ?? '';

if (
    $name === '' ||
    mb_strlen($name) > 100 ||
    !filter_var($email, FILTER_VALIDATE_EMAIL) ||
    strlen($email) > 150 ||
    !preg_match('/^[0-9+().\-\s]{7,20}$/', $phone) ||
    $terms !== 'yes' ||
    strlen($password) < 8 ||
    strlen($password) > 72 ||
    !preg_match('/^[\x20-\x7E]+$/', $password)
) {
    http_response_code(422);
    exit('Invalid details. Please check the form and try again.');
}

if (!hash_equals($password, $confirm)) {
    http_response_code(422);
    exit('Passwords do not match. Please go back and try again.');
}

// Store a secure password hash, never the plain-text password.
$passwordHash = password_hash($password, PASSWORD_DEFAULT);

try {
    $sql = "INSERT INTO users (name, email, phone, password)
            VALUES (:name, :email, :phone, :password)";

    $stmt = $pdo->prepare($sql);
    $stmt->execute([
        ':name' => $name,
        ':email' => $email,
        ':phone' => $phone,
        ':password' => $passwordHash
    ]);

    header('Location: signup.html?success=1', true, 303);
    exit;

} catch (PDOException $e) {
    if ($e->getCode() === '23000') {
        http_response_code(409);
        exit('This email may already be registered. Please try another email.');
    }

    error_log($e->getMessage());
    http_response_code(500);
    exit('Unable to create your account right now. Please try again later.');
}
?>