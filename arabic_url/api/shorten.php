<?php
require __DIR__ . '/config.php';
header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
$origin = $_SERVER['HTTP_ORIGIN'] ?? ($_SERVER['HTTP_REFERER'] ?? '');
if (strpos($origin, parse_url($GLOBALS['BASE_URL'], PHP_URL_HOST)) !== false) {
    header('Access-Control-Allow-Origin: ' . $origin);
} else {
    header('Access-Control-Allow-Origin: ' . $GLOBALS['BASE_URL']);
}
header('Access-Control-Allow-Methods: POST, OPTIONS');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

try {
    session_start();
    $payload = json_decode(file_get_contents('php://input'), true) ?? [];
    $long = trim($payload['url'] ?? '');
    $custom = isset($payload['custom']) ? trim($payload['custom']) : null;
    $recaptcha = trim($payload['recaptcha'] ?? '');

    if (!is_valid_url($long)) throw new Exception('رابط غير صالح — استخدم https:// أو http://');
    if (!empty($recaptcha) && !verify_recaptcha($recaptcha)) throw new Exception('فشل التحقق من reCAPTCHA');
    if (!check_webrisk($long)) throw new Exception('تم رفض الرابط لاحتوائه على محتوى ضار');

    // Basic blacklist
    $blacklist = ['malicious.example'];
    foreach ($blacklist as $b) if (stripos($long,$b)!==false) throw new Exception('الرابط محظور');

    $pdo = pdo();

    // rate limit by IP
    $ip_bin = client_ip_bin();
    if ($ip_bin) {
        $st = $pdo->prepare('SELECT COUNT(*) AS c FROM links WHERE creator_ip = ? AND created_at > (NOW() - INTERVAL 1 DAY)');
        $st->execute([$ip_bin]);
        $row = $st->fetch();
        if ($row && (int)$row['c'] >= (int)$GLOBALS['RATE_LIMIT_PER_DAY']) throw new Exception('تجاوزت حد إنشاء الروابط اليوم');
    }

    // user association (optional)
    $user_id = null;
    if (!empty($_SESSION['user_id'])) $user_id = (int)$_SESSION['user_id'];

    $pdo->beginTransaction();
    if ($custom !== null && $custom !== '') {
        if (!is_arabic_slug($custom)) throw new Exception('المسمى المخصص يجب أن يكون حروف عربية فقط');
        if (mb_strlen($custom,'UTF-8') < MIN_LEN) throw new Exception('المسمى قصير جدًا');
        $st = $pdo->prepare('SELECT id FROM links WHERE slug = ? LIMIT 1'); $st->execute([$custom]);
        if ($st->fetch()) throw new Exception('المسمى محجوز');
        $st = $pdo->prepare('INSERT INTO links (user_id, slug, long_url, creator_ip) VALUES (?,?,?,?)');
        $st->execute([$user_id, $custom, $long, $ip_bin]);
        $slug = $custom;
    } else {
        $st = $pdo->prepare('INSERT INTO links (user_id, slug, long_url, creator_ip) VALUES (?, "", ?, ?)');
        $st->execute([$user_id, $long, $ip_bin]);
        $id = (int)$pdo->lastInsertId();
        $slug = baseN_encode_ar($id + ID_OFFSET);
        $tries = 0;
        while ($tries < 5) {
            $up = $pdo->prepare('UPDATE links SET slug = ? WHERE id = ? AND slug = ""');
            $up->execute([$slug, $id]);
            if ($up->rowCount()>0) break;
            $tries++; $slug = baseN_encode_ar($id + ID_OFFSET + $tries);
        }
        if ($tries >= 5) throw new Exception('فشل إنشاء المسمّى');
    }
    $pdo->commit();
    echo json_encode(['ok'=>true,'short_url'=>rtrim($BASE_URL,'/').'/'.$slug,'slug'=>$slug], JSON_UNESCAPED_UNICODE);
} catch (Throwable $e) {
    if (isset($pdo) && $pdo->inTransaction()) $pdo->rollBack();
    http_response_code(400);
    echo json_encode(['ok'=>false,'error'=>$e->getMessage()], JSON_UNESCAPED_UNICODE);
}
?>