<?php
// CONFIG: عدّل القيم هنا أو ضعها كمتغيرات بيئة (مفضّل في الإنتاج)
$DB_HOST = getenv('DB_HOST') ?: 'localhost';
$DB_NAME = getenv('DB_NAME') ?: 'arabicshort';
$DB_USER = getenv('DB_USER') ?: 'DB_USERNAME'; // ← غيّرها
$DB_PASS = getenv('DB_PASS') ?: 'DB_PASSWORD'; // ← غيّرها

$BASE_URL = getenv('BASE_URL') ?: 'https://رابط.موقع'; // ← ضع دومينك هنا
// Google OAuth (set as env vars or here)
$GOOGLE_CLIENT_ID = getenv('GOOGLE_CLIENT_ID') ?: '';
$GOOGLE_CLIENT_SECRET = getenv('GOOGLE_CLIENT_SECRET') ?: '';

$RATE_LIMIT_PER_DAY = getenv('RATE_LIMIT_PER_DAY') ?: 200; // عدد الروابط المسموح إنشاؤها لكل IP يوميًا

// reCAPTCHA (v2/v3) - ضع المفاتيح في env أو هنا
$RECAPTCHA_SECRET = getenv('RECAPTCHA_SECRET') ?: ''; // ضع مفتاح السيرفر هنا
$RECAPTCHA_MIN_SCORE = 0.5; // لو تستخدم v3

// Google Web Risk API Key (اختياري) - لو عندك مفعل API
$WEBRISK_API_KEY = getenv('WEBRISK_API_KEY') ?: ''; // اتركه فارغًا إذا لم تستخدم

// أبجدية عربية محددة (28 حرف)
const AR_ALPHABET = 'ابتثجحخدذرزسشصضطظعغفقكلمنهوي';
const MIN_LEN = 3;
const ID_OFFSET = 1000;
const FREE_INTERSTITIAL = true; // صفحة إعلانية للمجانيين

// --- وظائف مساعدة ---
function pdo(): PDO {
    global $DB_HOST, $DB_NAME, $DB_USER, $DB_PASS;
    $dsn = "mysql:host={$DB_HOST};dbname={$DB_NAME};charset=utf8mb4";
    $opt = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ];
    return new PDO($dsn, $DB_USER, $DB_PASS, $opt);
}

function client_ip_bin(): ?string {
    $ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? null;
    return $ip ? @inet_pton($ip) : null;
}

function ip_text_to_bin(string $ip): ?string {
    return @inet_pton($ip);
}

function is_valid_url(string $u): bool {
    if (!preg_match('~^https?://~i', $u)) return false;
    return (bool) filter_var($u, FILTER_VALIDATE_URL);
}

function is_arabic_slug(string $s): bool {
    return (bool) preg_match('/^[ابتثجحخدذرزسشصضطظعغفقكلمنهوي]+$/u', $s);
}

function baseN_encode_ar(int $num): string {
    $alphabet = preg_split('//u', AR_ALPHABET, -1, PREG_SPLIT_NO_EMPTY);
    $base = count($alphabet);
    if ($num === 0) return $alphabet[0];
    $out = '';
    while ($num > 0) {
        $rem = $num % $base;
        $out = $alphabet[$rem] . $out;
        $num = intdiv($num, $base);
    }
    while (mb_strlen($out, 'UTF-8') < MIN_LEN) $out = $alphabet[0] . $out;
    return $out;
}

// Authentication & users (email + oauth placeholders)
function create_user(string $email, string $password): array {
    $pdo = pdo();
    $hash = password_hash($password, PASSWORD_DEFAULT);
    $st = $pdo->prepare('INSERT INTO users (email, pass_hash) VALUES (?,?)');
    $st->execute([$email, $hash]);
    return $pdo->query('SELECT * FROM users WHERE id = ' . (int)$pdo->lastInsertId())->fetch();
}

function find_user_by_email(string $email) {
    $pdo = pdo();
    $st = $pdo->prepare('SELECT * FROM users WHERE email = ? LIMIT 1');
    $st->execute([$email]);
    return $st->fetch();
}

function find_or_create_oauth_user(string $provider, string $provider_id, string $email = null) {
    $pdo = pdo();
    $st = $pdo->prepare('SELECT * FROM users WHERE oauth_provider = ? AND oauth_id = ? LIMIT 1');
    $st->execute([$provider, $provider_id]);
    $u = $st->fetch();
    if ($u) return $u;
    // create new user (email may be null)
    $ins = $pdo->prepare('INSERT INTO users (email, oauth_provider, oauth_id) VALUES (?,?,?)');
    $ins->execute([$email, $provider, $provider_id]);
    return $pdo->query('SELECT * FROM users WHERE id = ' . (int)$pdo->lastInsertId())->fetch();
}

function login_user_session(array $user) {
    if (session_status() !== PHP_SESSION_ACTIVE) session_start();
    session_regenerate_id(true);
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['user_email'] = $user['email'] ?? '';
    return true;
}

function current_user() {
    if (session_status() !== PHP_SESSION_ACTIVE) session_start();
    if (empty($_SESSION['user_id'])) return null;
    $pdo = pdo();
    $st = $pdo->prepare('SELECT * FROM users WHERE id = ? LIMIT 1');
    $st->execute([$_SESSION['user_id']]);
    return $st->fetch();
}

function require_login() {
    $u = current_user();
    if (!$u) {
        header('Location: /login.php');
        exit;
    }
    return $u;
}

function require_paid_member() {
    $u = require_login();
    if (!(int)$u['is_paid']) {
        header('Location: /subscribe.php');
        exit;
    }
    return $u;
}
?>