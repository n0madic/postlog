<?
session_start();
//// BEGIN CONFIG ////
define('ADMIN_PASS', 'f379eaf3c831b04de153469d1bec345e');
define('LOGFILE', 'mail.log');
///// END CONFIG /////

// Logout
if (isset($_REQUEST['logout'])) {
	unset($_SESSION['u_login']);
	session_destroy();
	header( "Location: ".$_SERVER['SCRIPT_NAME']); 
	die();
}
// Check password
if(isset($_POST['passwd'])){
    if(md5($_POST['passwd']) == ADMIN_PASS){
        $_SESSION['u_login']='YES';
    } else {
		unset($_SESSION['u_login']);
		session_destroy();
	}
}
// Check authorization
if(!isset($_POST['passwd']) and !empty($_POST) and !isset($_SESSION['u_login'])){
	header( "Location: ".$_SERVER['SCRIPT_NAME']); 
	die('Access denied!');
}

function tailCustom($filepath, $lines = 1, $adaptive = true) { // by https://gist.github.com/lorenzos/1711e81a9162320fde20
	// Open file
	$f = @fopen($filepath, "rb");
	if ($f === false) return false;
	// Sets buffer size
	if (!$adaptive) $buffer = 4096;
	else $buffer = ($lines < 2 ? 64 : ($lines < 10 ? 512 : 4096));
	// Jump to last character
	fseek($f, -1, SEEK_END);
	// Read it and adjust line number if necessary
	// (Otherwise the result would be wrong if file doesn't end with a blank line)
	if (fread($f, 1) != "\n") $lines -= 1;
	// Start reading
	$output = '';
	$chunk = '';
	// While we would like more
	while (ftell($f) > 0 && $lines >= 0) {
		// Figure out how far back we should jump
		$seek = min(ftell($f), $buffer);
		// Do the jump (backwards, relative to where we are)
		fseek($f, -$seek, SEEK_CUR);
		// Read a chunk and prepend it to our output
		$output = ($chunk = fread($f, $seek)) . $output;
		// Jump back to where we started reading
		fseek($f, -mb_strlen($chunk, '8bit'), SEEK_CUR);
		// Decrease our line counter
		$lines -= substr_count($chunk, "\n");
	}
	// While we have too many lines
	// (Because of buffer size we might have read too many)
	while ($lines++ < 0) {
		// Find first newline and remove all text before that
		$output = substr($output, strpos($output, "\n") + 1);
	}
	// Close file and return
	fclose($f);
	return explode("\n", trim($output));
}

// Set lines count
if (!empty($_SESSION['count'])) {
	$count = $_SESSION['count'];
} else {
	$count = 100;
}
if (!empty($_REQUEST['count'])) {
	if (is_numeric($_REQUEST['count'])) {
		$count = trim($_REQUEST['count']);
	} else {
		$count  = $_SESSION['count'];
	}
}
$_SESSION['count'] = $count;
// Open log file
if (!empty($_REQUEST['search'])) {
		$logfile = array();
		$handle = @fopen(LOGFILE, "r");
		if ($handle) {
			while (!feof($handle))
			{
				$buffer = fgets($handle);
				if(strpos($buffer, trim($_REQUEST['search'])) !== FALSE)
					$logfile[] = $buffer;
			}
			fclose($handle);
		} else {
			die("[ERROR] Don't open log file: ".LOGFILE);
		}
		if (empty($logfile)) die('Not found');
} else {
	if (!$logfile = tailCustom(LOGFILE, $count)) {
		die("[ERROR] Don't open log file: ".LOGFILE);
	}
}

function getSubStr($str,$regex,$index) {
	preg_match($regex, $str, $matches, PREG_OFFSET_CAPTURE);
	return $matches[$index][0];
}

$j = 0;
for ($i = 0; $i < count($logfile); $i++) {
	if (!empty($logfile[$i])) {
		$logrows[$j]['datetime'] = GetSubStr($logfile[$i],'/^[a-zA-Z]{3}\s+\d+\s\d{2}:\d{2}:\d{2}/', 0);
		if (strpos($logfile[$i],"NOQUEUE: reject")) {
			$logrows[$j]['status'] = 'reject';
			$logrows[$j]['from'] = GetSubStr($logfile[$i],'/from=<(.*?)>/', 1);;
			$logrows[$j]['to'] = GetSubStr($logfile[$i],'/to=<(.*?)>/', 1);
			$logrows[$j]['text'] = substr($logfile[$i], strpos($logfile[$i], 'reject: ')+8);
		} elseif (strpos($logfile[$i],"warning: ")) {
			$logrows[$j]['status'] = 'warning';
			$logrows[$j]['text'] = substr($logfile[$i], strpos($logfile[$i], 'warning: ')+9);
		} elseif (strpos($logfile[$i],"cbpolicyd")) {
			$logrows[$j]['status'] = 'greylisted';
			$logrows[$j]['from'] = GetSubStr($logfile[$i],'/from=(.*?),/', 1);;
			$logrows[$j]['to'] = GetSubStr($logfile[$i],'/to=(.*?),/', 1);
			$logrows[$j]['text'] = substr($logfile[$i], strpos($logfile[$i], 'action='));
		} elseif (strpos($logfile[$i],"amavis")) {
			$logrows[$j]['status'] = 'antispam';
			$logrows[$j]['from'] = GetSubStr($logfile[$i],'/\s<(.*?)>/', 1);;
			$logrows[$j]['to'] = GetSubStr($logfile[$i],'/->\s<(.*?)>/', 1);
			$logrows[$j]['text'] = substr($logfile[$i], strpos($logfile[$i], 'Passed'));
		} elseif (strpos($logfile[$i],"status=sent")) {
			$logrows[$j]['status'] = 'sent';
			$logrows[$j]['to'] = GetSubStr($logfile[$i],'/to=<(.*?)>/', 1);
			$logrows[$j]['text'] = substr($logfile[$i], strpos($logfile[$i], ']: ')+3);
		} else {
			$logrows[$j]['status'] = 'garbage';
			$logrows[$j]['text'] = substr($logfile[$i], strpos($logfile[$i], 'postfix/'));
		}
		$logrows[$j]['fulltext'] = $logfile[$i];
		$j++;
	}
}
if (isset($_REQUEST['filter'])) {
	$filter = trim($_REQUEST['filter']);
} else {
	$filter = "";
}

?>
<html>
<head>
<title>Postfix log viewer</title>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/bootstrap/latest/css/bootstrap.min.css">
<script src="//ajax.googleapis.com/ajax/libs/jquery/2.1.1/jquery.min.js"></script>
<script src="//maxcdn.bootstrapcdn.com/bootstrap/latest/js/bootstrap.min.js"></script>
<link href="//cdnjs.cloudflare.com/ajax/libs/x-editable/1.5.0/bootstrap3-editable/css/bootstrap-editable.css" rel="stylesheet"/>
<script src="//cdnjs.cloudflare.com/ajax/libs/x-editable/1.5.0/bootstrap3-editable/js/bootstrap-editable.min.js"></script>
<script type="text/javascript">
    function goToBottom() {
	location.href = "#bottom";
    }
</script>
</head>
<body onload="goToBottom();">
<div class="container">
<nav class="navbar navbar-default" role="navigation">
  <div class="container-fluid">
    <!-- Brand and toggle get grouped for better mobile display -->
    <div class="navbar-header">
      <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#bs-navbar-collapse-1">
        <span class="sr-only">Toggle navigation</span>
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
      </button>
      <a class="navbar-brand" href="<?echo $_SERVER['SCRIPT_NAME'];?>">Postfix log viewer</a>
    </div>
<? if(isset($_SESSION['u_login'])){ ?>
    <!-- Collect the nav links, forms, and other content for toggling -->
    <div class="collapse navbar-collapse" id="bs-navbar-collapse-1">
      <ul class="nav navbar-nav">
        <li class="dropdown">
         <button class="btn btn-default navbar-btn dropdown-toggle" data-toggle="dropdown"><span class="glyphicon glyphicon-filter"></span> Filters <?echo $filter !== '' ? ' (enabled) ' : '';?><span class="caret"></span></button>
          <ul class="dropdown-menu" role="menu">
            <li data-selected-item="true"><a href="<?echo $_SERVER['SCRIPT_NAME'];?>">Disable<?echo $filter == '' ? ' <span class="glyphicon glyphicon-ok text-right"></span>' : '';?></a></li>
            <li class="divider"></li>
            <li><a href="?filter=success">Only successful<?echo $filter == 'success' ? ' <span class="glyphicon glyphicon-ok"></span>' : '';?></a></li>
            <li><a href="?filter=fails">Only fails<?echo $filter == 'fails' ? ' <span class="glyphicon glyphicon-ok"></span>' : '';?></a></li>
            <li class="divider"></li>
            <li><a href="?filter=nogarbage">No garbage<?echo $filter <> '' ? ' <span class="glyphicon glyphicon-ok"></span>' : '';?></a></li>
          </ul>
        </li>
      </ul>
      <form class="navbar-form navbar-left" role="search" action="<?echo $_SERVER['REQUEST_URI'];?>" method="post">
        <div class="form-group">
          <input type="text" size="30" name="search" class="form-control" placeholder="Search in log" value="<?echo isset($_REQUEST['search']) ? $_REQUEST['search'] : '';?>">
        </div>
        <button type="submit" class="btn btn-primary"><span class="glyphicon glyphicon-search"></span> Search</button>
      </form>
      <form class="navbar-form navbar-left" action="<?echo $_SERVER['REQUEST_URI'];?>" method="post">
        <div class="form-group">
		Count lines 
          <input type="text" size="9" name="count" class="form-control" placeholder="Enter count" value="<? echo $count;?>">
        </div>
        <button type="submit" class="btn btn-info"><span class="glyphicon glyphicon-ok"></span> Apply</button>
      </form>
      <ul class="nav navbar-nav navbar-right">
        <a href="?logout" class="btn btn-warning navbar-btn"><span class="glyphicon glyphicon-log-out"></span> Logout</a>
      </ul>
    </div><!-- /.navbar-collapse -->
<? } ?>
  </div><!-- /.container-fluid -->
</nav>
<?
if(!isset($_SESSION['u_login'])){
    ?>
	<label for="InputPassword1">Please enter password for access:</label>
	<form class="form-inline" role="form" method="post">
	<div class="form-group">
		<label class="sr-only" for="InputPassword2">Password</label>
		<input type="password" name="passwd" class="form-control" id="InputPassword2" placeholder="Password">
	</div>
	<button type="submit" class="btn btn-large btn-primary">Sign in</button>
	</form>
	</div>
	</body>
	</html>
<?
	exit;
}
?>
<table id="log" class="table table-hover table-condensed">
<thead><tr><th width="15%">Datetime</th><th width="15%">Status</th><th>FROM</th><th>TO</th></tr></thead>
<tbody>
<?
for ($i = 0; $i < count($logrows); $i++) {
	if (isset($_REQUEST['status'])) {
		if ($_REQUEST['status'] !== $logrows[$i]['status']) continue;
	}
	$text = htmlspecialchars($logrows[$i]['text']);
	switch ($logrows[$i]['status']) {
		case "reject":
			if ($filter == 'success') continue 2;
			$rowstyle = "danger";
			// highlight reject reason
			$text = preg_replace('/(\d{3}\s\d\.\d\.\d.*); from/', '<b>$1</b>; from', $text);
			break;
		case "warning":
			if ($filter == 'success') continue 2;
			$rowstyle = "warning";
			break;
		case "greylisted":
			if (strpos($logrows[$i]['text'], "action=pass") !== false) {
				if ($filter == 'fails') continue 2;
				$rowstyle = "info";
			} else {
				if ($filter == 'success') continue 2;
				$rowstyle = "warning";
			}
			$text = preg_replace('/(action=|reason=)(.+)(?:\,|$)/U', '$1<b>$2</b>.', $text);
			break;
		case "antispam":
			if (strpos($logrows[$i]['text'], "Passed CLEAN") !== false) {
				if ($filter == 'fails') continue 2;
				$rowstyle = "info";
			} else {
				if ($filter == 'success') continue 2;
				$rowstyle = "warning";
			}
			break;
		case "sent":
			if ($filter == 'fails') continue 2;
			$rowstyle = "success";
			// highlight sent status
			$text = preg_replace('/status=sent \((.*)\)/', '(<b>$1</b>)', $text);
			break;
		default:
			$rowstyle = "default";
			if ($filter <> "") continue 2;
	}
	echo '<tr class="'.$rowstyle.'">';
	echo '<td><strong>'.$logrows[$i]['datetime'].'</strong></td>';
	echo '<td><a href="?status='.$logrows[$i]['status'].'"><button type="button" class="btn btn-xs btn-'.$rowstyle.'">'.$logrows[$i]['status'].'</button></a></td>';
	echo "<td><em><strong>";
	if (isset($logrows[$i]['from'])) echo $logrows[$i]['from'];
	echo "</strong></em></td>";
	echo "<td><em><strong>";
	if (isset($logrows[$i]['to'])) echo $logrows[$i]['to'];
	echo "</strong></em></td></tr>";
	// highlight e-mails
	$text = preg_replace('/([\w\-][\w\-\.]+@[\w\-][\w\-\.]+[a-zA-Z]{1,4})/', '<a href="?search=$0">$0</a>', $text);
	// highlight IP
	$text = preg_replace('/\[\b(?!127)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/', '[<a href="?search=$1">$1</a>]', $text);
	// highlight hostname
	$text = preg_replace('/(from\s|client=|helo=)(.+\.\w{2,})\[/', '$1<b>$2</b>[', $text);
	// highlight Message ID
	$text = preg_replace('/([A-Z0-9]{11})(?:\)|:|,|;)+/', '<a href="?search=$1">$0</a>', $text);
	echo '<tr class="'.$rowstyle.'"><td>Details:</td><td colspan="3">'.$text.'</td></tr>';
	echo '<tr><td colspan="4"></td></tr>';
}
?>
</table>
<a name="bottom" class="back-to-top glyphicon glyphicon-arrow-up well well-sm" href="#top" title="Top"></a>
</div> <!-- /.container -->
</body>
</html>