<?php
if ($_GET) {
    echo "Hello, " . $_GET['name'] . "!";
}
elseif ($_POST) {
    echo "Hello, " . $_POST['name'] . "!";
}
?>
