<?php
libxml_disable_entity_loader(true); // Désactiver le chargement des entités externes
libxml_set_external_entity_loader(static function () { return null; }); // Set un entity loader pour négliger les entrées
$xmlfile = file_get_contents('php://input');
$dom = new DOMDocument();
$dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD);
$info = simplexml_import_dom($dom);
$name = $info->name;
$tel = $info->tel;
$email = $info->email;
$password = $info->password;

echo "Sorry, $email is already registered!";
?>
