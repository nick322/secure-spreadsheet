<?php

require 'vendor/autoload.php';

use Nick\SecureSpreadsheet\Encrypt;

// output file
$test = new Encrypt;
$test->input('Book1.xlsx')
    ->password('111')
    ->output('bb2.xlsx');

// output file with nofile
$test = new Encrypt(true);
$out = $test->input('Book1.xlsx')
    ->password('111')
    ->output();

// output file with nofile and set temp path folder
$test = new Encrypt(true);
$out = $test->input('Book1.xlsx')
    ->setTempPathFolder(__DIR__.DIRECTORY_SEPARATOR.'tmp')
    ->password('111')
    ->output();


// output file with set temp path folder
$test = new Encrypt;
$test->input('Book1.xlsx')
    ->setTempPathFolder(__DIR__.DIRECTORY_SEPARATOR.'tmp')
    ->password('111')
    ->output('bb4.xlsx');
