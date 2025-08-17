<?php
require __DIR__ . '/api/config.php';
session_start();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    $pass = trim($_POST['pass'] ?? '');
    $u = find_user_by_email($email);
    if (!$u || !password_verify($pass, $u['pass_hash'])) {
        $err = 'خاطئ البريد أو كلمة المرور.';
    } else {
        login_user_session($u);
        header('Location: /dashboard.php'); exit;
    }
}
?><!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><title>دخول</title>
<style>body{font-family:system-ui;padding:20px}form{max-width:480px}</style>
<h1>تسجيل دخول</h1>
<?php if(!empty($err)) echo '<p style="color:red">'.htmlspecialchars($err).'</p>'; ?>
<form method="post">
<label>البريد<input name="email" required></label><br><br>
<label>كلمة المرور<input name="pass" type="password" required></label><br><br>
<button>دخول</button>
</form>
</html>