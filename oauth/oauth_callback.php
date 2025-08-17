<?php
require __DIR__ . '/../api/config.php';
session_start();

$provider = $_GET['provider'] ?? 'google';
if ($provider !== 'google') {
    http_response_code(400);
    echo 'Provider not supported';
    exit;
}

// validate state to prevent CSRF
if (empty($_GET['state']) || empty($_SESSION['oauth_state']) || !hash_equals($_SESSION['oauth_state'], $_GET['state'])) {
    http_response_code(400);
    echo 'Invalid OAuth state';
    exit;
}
unset($_SESSION['oauth_state']);

if (empty($_GET['code'])) {
    http_response_code(400);
    echo 'No authorization code provided';
    exit;
}

$code = $_GET['code'];

// exchange code for tokens
$token_endpoint = 'https://oauth2.googleapis.com/token';
$post_fields = [
    'code' => $code,
    'client_id' => $GOOGLE_CLIENT_ID,
    'client_secret' => $GOOGLE_CLIENT_SECRET,
    'redirect_uri' => rtrim($BASE_URL, '/') . '/oauth/oauth_callback.php?provider=google',
    'grant_type' => 'authorization_code'
];

$ch = curl_init($token_endpoint);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post_fields));
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded']);
curl_setopt($ch, CURLOPT_TIMEOUT, 10);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
$res = curl_exec($ch);
$curl_err = curl_error($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($res === false) {
    http_response_code(500);
    echo 'Token request failed: ' . htmlspecialchars($curl_err);
    exit;
}

$token = json_decode($res, true);
if (!isset($token['access_token'])) {
    http_response_code(400);
    echo 'Token response error: ' . htmlspecialchars($res);
    exit;
}

$access_token = $token['access_token'];

// fetch userinfo
$ch = curl_init('https://openidconnect.googleapis.com/v1/userinfo');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Authorization: Bearer ' . $access_token]);
curl_setopt($ch, CURLOPT_TIMEOUT, 10);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
$res2 = curl_exec($ch);
$curl_err2 = curl_error($ch);
curl_close($ch);

if ($res2 === false) {
    http_response_code(500);
    echo 'Userinfo request failed: ' . htmlspecialchars($curl_err2);
    exit;
}

$userinfo = json_decode($res2, true);
if (empty($userinfo['sub'])) {
    http_response_code(400);
    echo 'Invalid user info response';
    exit;
}

$provider_id = $userinfo['sub'];
$email = $userinfo['email'] ?? null;
$email_verified = isset($userinfo['email_verified']) ? (bool)$userinfo['email_verified'] : false;

// SECURITY NOTE: prefer linking accounts when email exists and is verified.
$pdo = pdo();

// If email exists in DB with a non-OAuth account, prefer linking if email_verified
if ($email && $email_verified) {
    $st = $pdo->prepare('SELECT * FROM users WHERE email = ? LIMIT 1');
    $st->execute([$email]);
    $existing = $st->fetch();
    if ($existing) {
        // update OAuth fields if not set
        if (empty($existing['oauth_provider']) || empty($existing['oauth_id'])) {
            $up = $pdo->prepare('UPDATE users SET oauth_provider = ?, oauth_id = ? WHERE id = ?');
            $up->execute(['google', $provider_id, $existing['id']]);
            $user = $existing;
            $user['oauth_provider'] = 'google';
            $user['oauth_id'] = $provider_id;
        } else {
            $user = $existing;
        }
        login_user_session($user);
        header('Location: ' . ( (int)$user['is_paid'] ? '/dashboard.php' : '/subscribe.php' ));
        exit;
    }
}

// find by provider/id or create new
$st = $pdo->prepare('SELECT * FROM users WHERE oauth_provider = ? AND oauth_id = ? LIMIT 1');
$st->execute(['google', $provider_id]);
$user = $st->fetch();
if (!$user) {
    $ins = $pdo->prepare('INSERT INTO users (email, oauth_provider, oauth_id) VALUES (?,?,?)');
    $ins->execute([$email, 'google', $provider_id]);
    $user = $pdo->query('SELECT * FROM users WHERE id = ' . (int)$pdo->lastInsertId())->fetch();
}

// login and redirect to appropriate place
login_user_session($user);
header('Location: ' . ( (int)$user['is_paid'] ? '/dashboard.php' : '/subscribe.php' ));
exit;
?>