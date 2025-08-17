<?php
require __DIR__ . '/api/config.php';
session_start();
$u = require_paid_member();
$pdo = pdo();
$st = $pdo->prepare('SELECT * FROM links WHERE user_id = ? ORDER BY id DESC LIMIT 200');
$st->execute([$u['id']]);
$rows = $st->fetchAll();
?><!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><title>لوحة الأعضاء</title>
<style>body{font-family:system-ui;padding:20px} table{width:100%;border-collapse:collapse} th,td{padding:8px;border-bottom:1px solid #eee}</style>
<h1>لوحة العضو — <?=htmlspecialchars($u['email'] ?? 'مستخدم') ?></h1>
<p>يمكن للأعضاء المشتركين إدارة روابطهم من هنا.</p>
<table>
<tr><th>#</th><th>القصير</th><th>الأصلي</th><th>نقرات</th><th>أضيف في</th></tr>
<?php foreach($rows as $r): ?>
<tr>
<td><?= (int)$r['id'] ?></td>
<td><a href="/<?=htmlspecialchars($r['slug'], ENT_QUOTES, 'UTF-8')?>" target="_blank"><?=htmlspecialchars($r['slug'], ENT_QUOTES, 'UTF-8')?></a></td>
<td style="max-width:500px;overflow:hidden;white-space:nowrap"><?=htmlspecialchars($r['long_url'], ENT_QUOTES, 'UTF-8')?></td>
<td><?= (int)$r['clicks'] ?></td>
<td><?= htmlspecialchars($r['created_at'], ENT_QUOTES, 'UTF-8') ?></td>
</tr>
<?php endforeach; ?>
</table>
</html>