<?php
if ($_GET) {
    echo "Hello, " . $_GET['name'] . "!\n";
}
elseif ($_POST) {
    echo "Hello, " . $_POST['name'] . "!\n";
}
?>
