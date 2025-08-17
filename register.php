<?php
require __DIR__ . '/api/config.php';
session_start();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    $pass = trim($_POST['pass'] ?? '');
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $err = 'بريد إلكتروني غير صالح';
    elseif (strlen($pass) < 6) $err = 'كلمة المرور قصيرة';
    else {
        if (find_user_by_email($email)) $err = 'البريد مسجل مسبقًا. سجل دخول بدلًا من ذلك.';
        else {
            $u = create_user($email, $pass);
            login_user_session($u);
            header('Location: /dashboard.php'); exit;
        }
    }
}
?><!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><title>تسجيل</title>
<style>body{font-family:system-ui;padding:20px} form{max-width:480px}</style>
<h1>سجل حساب جديد</h1>
<?php if(!empty($err)) echo '<p style="color:red">'.htmlspecialchars($err).'</p>'; ?>
<form method="post">
<label>البريد الإلكتروني<input name="email" required></label><br><br>
<label>كلمة المرور<input name="pass" type="password" required></label><br><br>
<button>سجل</button>
</form>

<hr>
<p>أو سجل عبر</p>
<div>
  <a href="/oauth/oauth_start.php?provider=google">Google</a> |
  <a href="/oauth/oauth_start.php?provider=facebook">Facebook</a> |
  <a href="/oauth/oauth_start.php?provider=twitter">Twitter</a> |
  <a href="/oauth/oauth_start.php?provider=linkedin">LinkedIn</a>
</div>
</html>