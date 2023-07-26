<?php

namespace Illuminate\Tests\Auth;

use PHPUnit\Framework\TestCase;
use Nick\SecureSpreadsheet\Encrypt;

class EncryptorTest extends TestCase
{
    protected function setUp(): void
    {
        if (file_exists('bb.xlsx')) unlink('bb.xlsx');
    }

    public function testEncryptor()
    {
        (new Encrypt())->input('Book1.xlsx')->password('111')->output('bb.xlsx');
        $this->assertFileExists('bb.xlsx');
    }

    public function testEncryptorWithBinaryData()
    {
        $data = 'Book1.xlsx';
        $fp = fopen($data, 'rb');
        $binaryData = fread($fp, filesize($data));
        fclose($fp);
        $str = (new Encrypt($nofile = true))->input($binaryData)->password('111')->output();
        $this->assertEquals(12288, strlen($str));
    }
}
