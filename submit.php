<?php
declare(strict_types=1);

session_start();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: signup.html');
    exit;
}

// Database configuration
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

// Securely hash the password
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

    // Show success page only after successful database insertion
    http_response_code(200);
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Registration Successful | Fortune Cloud</title>

        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }

            body {
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                padding: 20px;
                font-family: Arial, sans-serif;
                background: linear-gradient(
                    135deg, #e5e7ff, #dff7ff, #f5e9ff
                );
            }

            .success-card {
                width: 100%;
                max-width: 460px;
                padding: 40px 28px;
                background: white;
                border-radius: 24px;
                text-align: center;
                box-shadow: 0 20px 60px rgba(76, 81, 175, .15);
            }

            .check {
                width: 85px;
                height: 85px;
                margin: 0 auto 25px;
                display: flex;
                align-items: center;
                justify-content: center;
                border-radius: 50%;
                background: #dcfce7;
                color: #16a34a;
                font-size: 45px;
                font-weight: bold;
            }

            .brand {
                color: #7657f6;
                font-size: 22px;
                font-weight: bold;
                margin-bottom: 28px;
            }

            h1 {
                color: #19213b;
                font-size: 27px;
                margin-bottom: 14px;
            }

            .message {
                color: #788198;
                font-size: 15px;
                line-height: 1.8;
                margin-bottom: 25px;
            }

            .verified {
                display: inline-block;
                padding: 10px 16px;
                border-radius: 30px;
                background: #dcfce7;
                color: #15803d;
                font-size: 13px;
                font-weight: bold;
                margin-bottom: 28px;
            }

            .home-btn {
                display: block;
                padding: 15px;
                border-radius: 11px;
                background: linear-gradient(100deg, #7657f6, #4e83f5);
                color: white;
                text-decoration: none;
                font-size: 14px;
                font-weight: bold;
            }

            .home-btn:hover {
                opacity: .9;
            }

            .footer {
                margin-top: 25px;
                color: #9aa1b2;
                font-size: 12px;
            }
        </style>
    </head>

    <body>
        <main class="success-card">
            <div class="brand">☁ Fortune Cloud</div>

            <div class="check">&#10003;</div>

            <h1>Registration Successful!</h1>

            <p class="message">
                Congratulations,
                <strong><?= htmlspecialchars(
                    $name, ENT_QUOTES, 'UTF-8'
                ) ?></strong>!<br>
                Your account has been created successfully.
                Thank you for joining Fortune Cloud.
            </p>

            <div class="verified">
                &#10003; SUCCESS — REGISTRATION VERIFIED
            </div>

            <a class="home-btn" href="signup.html">
                Back to Signup
            </a>

            <p class="footer">
                &copy; 2026 Fortune Cloud. All rights reserved.
            </p>
        </main>
    </body>
    </html>
    <?php
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
