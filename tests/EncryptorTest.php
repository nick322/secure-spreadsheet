<?php

namespace Illuminate\Tests\Auth;

use PHPUnit\Framework\TestCase;
use Nick\SecureSpreadsheet\Encrypt;

class EncryptorTest extends TestCase
{
    protected function setUp(): void
    {
        if(file_exists('bb.xlsx')) unlink('bb.xlsx');
    }

    public function testEncryptor()
    {
        (new Encrypt())->input('Book1.xlsx')->password('111')->output('bb.xlsx');
        $this->assertFileExists('bb.xlsx');
    }
}
