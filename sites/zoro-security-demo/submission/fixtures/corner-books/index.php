<?php
declare(strict_types=1);
$shelf = json_decode(file_get_contents(__DIR__ . '/shelf.json'), true, 512, JSON_THROW_ON_ERROR);
function h(string $text): string {
    return htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
$reading = $shelf['reading'];
?>
<!doctype html>
<html lang="ko">
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>골목책방 · 이달의 책</title>
<h1>이달의 책</h1>
<ul>
<?php foreach ($shelf['shelves'] as $item): ?>
  <li><strong><?= h($item['book']) ?></strong> · <?= h($item['place']) ?><p><?= h($item['note']) ?></p></li>
<?php endforeach; ?>
</ul>
<h2>토요일 낭독회</h2>
<p><?= h($reading['date']) ?> <?= h($reading['time']) ?> · <?= h($reading['book']) ?> · <?= (int)$reading['seats'] ?>석</p>
</html>
