<?php
$host = "localhost";
$dbname = "play safe";
$username = "if0_39218116"; // default XAMPP user
$password = "bhvaysigma1493"; // default XAMPP password (empty)

// Connect to database
$conn = new mysqli($host, $username, $password, $dbname);
if ($conn->connect_error) {
    die(json_encode(["status" => "error", "message" => "Connection failed"]));
}

// Get JSON input from JS
$data = json_decode(file_get_contents("php://input"), true);

// If JSON input is not found, fallback to form POST (just in case)
if (!$data && $_POST) {
    $data = $_POST;
}

$action = $data['action'] ?? '';

if ($action === 'signup') {
    $email = $conn->real_escape_string($data['email'] ?? '');
    $username = $conn->real_escape_string($data['username'] ?? '');
    $raw_password = $data['password'] ?? '';

    if ($email && $username && $raw_password) {
        $password = password_hash($raw_password, PASSWORD_BCRYPT);

        $check = $conn->query("SELECT * FROM users WHERE username = '$username'");
        if ($check->num_rows > 0) {
            echo json_encode(["status" => "error", "message" => "Username already exists"]);
        } else {
            $stmt = $conn->prepare("INSERT INTO users (email, username, password) VALUES (?, ?, ?)");
            $stmt->bind_param("sss", $email, $username, $password);
            if ($stmt->execute()) {
                echo json_encode(["status" => "success", "message" => "Signup successful"]);
            } else {
                echo json_encode(["status" => "error", "message" => "Signup failed"]);
            }
            $stmt->close();
        }
    } else {
        echo json_encode(["status" => "error", "message" => "Missing fields"]);
    }

} elseif ($action === 'login') {
    $username = $conn->real_escape_string($data['username'] ?? '');
    $password = $data['password'] ?? '';

    if ($username && $password) {
        $result = $conn->query("SELECT * FROM users WHERE username = '$username'");
        if ($result->num_rows === 1) {
            $user = $result->fetch_assoc();
            if (password_verify($password, $user['password'])) {
                echo json_encode(["status" => "success", "username" => $user['username']]);
            } else {
                echo json_encode(["status" => "error", "message" => "Invalid password"]);
            }
        } else {
            echo json_encode(["status" => "error", "message" => "User not found"]);
        }
    } else {
        echo json_encode(["status" => "error", "message" => "Missing login fields"]);
    }
}

$conn->close();
?>
