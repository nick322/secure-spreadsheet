<?php
require "vendor/autoload.php";

use Nick\SecureSpreadsheet\Encrypt;

$test = new Encrypt();
$test->input('Book1.xlsx')
    ->password('111')
    ->output('bb.xlsx');