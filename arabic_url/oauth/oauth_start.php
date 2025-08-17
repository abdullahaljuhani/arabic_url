<?php
require __DIR__ . '/../api/config.php';
session_start();

$provider = $_GET['provider'] ?? 'google';
if ($provider !== 'google') {
    http_response_code(400);
    echo 'Provider not supported';
    exit;
}

if (empty($GOOGLE_CLIENT_ID) || empty($GOOGLE_CLIENT_SECRET)) {
    echo 'Google OAuth not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in your environment or api/config.php';
    exit;
}

// create and store state for CSRF protection
$state = bin2hex(random_bytes(16));
$_SESSION['oauth_state'] = $state;

// redirect URI must exactly match the value registered in Google Console
$redirect_uri = rtrim($BASE_URL, '/') . '/oauth/oauth_callback.php?provider=google';

$params = [
    'client_id' => $GOOGLE_CLIENT_ID,
    'redirect_uri' => $redirect_uri,
    'response_type' => 'code',
    'scope' => 'openid email profile',
    'state' => $state,
    'access_type' => 'offline', // request refresh token (only returned on first consent)
    'prompt' => 'select_account consent'
];

$auth_url = 'https://accounts.google.com/o/oauth2/v2/auth?' . http_build_query($params);
header('Location: ' . $auth_url);
exit;
?>