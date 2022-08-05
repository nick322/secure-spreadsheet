#!php
<?php

use Silly\Application;
use Nick\SecureSpreadsheet\Encrypt;
use Symfony\Component\Console\Output\OutputInterface;

if (file_exists(__DIR__ . '/../vendor/autoload.php')) {
    require __DIR__ . '/../vendor/autoload.php';
} elseif (file_exists(__DIR__ . '/../../../autoload.php')) {
    require __DIR__ . '/../../../autoload.php';
} else {
    require getenv('HOME') . '/.composer/vendor/autoload.php';
}

$app = new Application('Secure spreadsheet', $version = '1.0.0');

$app->command(
    'run [--password=] [--input=] [--output=] ',
    function (OutputInterface $out, $password, $input, $output) {
        $encrypt = new Encrypt();
        $encrypt->input($input)
            ->password($password)
            ->output($output);
        $out->writeln('done.');
    }
)->descriptions('Encrypt and password protect sensitive XLSX files');

$app->run();
