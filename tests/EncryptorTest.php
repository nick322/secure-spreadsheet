<?php

namespace Illuminate\Tests\Auth;

use Nick\SecureSpreadsheet\Encrypt;
use PHPUnit\Framework\TestCase;

class EncryptorTest extends TestCase
{
    protected function setUp(): void
    {
        if (file_exists('bb.xlsx')) {
            unlink('bb.xlsx');
        }
    }

    public function test_encryptor()
    {
        (new Encrypt)->input('Book1.xlsx')->password('111')->output('bb.xlsx');
        $this->assertFileExists('bb.xlsx');
    }

    public function test_encryptor_with_binary_data()
    {
        $data = 'Book1.xlsx';
        $fp = fopen($data, 'rb');
        $binaryData = fread($fp, filesize($data));
        fclose($fp);
        $str = (new Encrypt($nofile = true))->input($binaryData)->password('111')->output();
        $this->assertEquals(12288, strlen($str));
    }

    public function test_encryptor_with_set_temp_path_folder()
    {
        (new Encrypt)->input('Book1.xlsx')->setTempPathFolder(dirname(__DIR__).DIRECTORY_SEPARATOR.'tmp')->password('111')->output('bb.xlsx');
        $this->assertFileExists('bb.xlsx');
    }
}
