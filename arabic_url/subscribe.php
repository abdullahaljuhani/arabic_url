<?php
require __DIR__ . '/api/config.php';
session_start();
$u = current_user();
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!$u) { header('Location: /login.php'); exit; }
    $pdo = pdo();
    $st = $pdo->prepare('UPDATE users SET is_paid = 1 WHERE id = ?');
    $st->execute([$u['id']]);
    header('Location: /dashboard.php'); exit;
}
?><!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><title>اشترك</title>
<style>body{font-family:system-ui;padding:20px}</style>
<h1>اختر باقتك</h1>
<p>إختر بين الاشتراك المجاني أو المدفوع. في النسخة التجريبية، اضغط اشترك للترقية مباشرة.</p>
<form method="post">
  <button>اشترك (مدفوع) — تجربة تجريبية</button>
</form>
</html>