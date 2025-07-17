<?php

namespace Nick\SecureSpreadsheet;

class PackageEncryptor
{
    public static function encrypt(
        string $cipherAlgorithm,
        string $cipherChaining,
        string $hashAlgorithm,
        int $blockSize,
        array $saltValue,
        array $key,
        callable $input
    ) {
        $tmpOutputChunk = tempnam(sys_get_temp_dir(), 'outputChunk');
        $tmpFileHeaderLength = tempnam(sys_get_temp_dir(), 'fileHeaderLength');
        $tmpFile = tempnam(sys_get_temp_dir(), 'file');

        if (is_callable($input) && is_a($in = $input(), 'Generator')) {
            $inputCount = 0;

            foreach ($in as $i => $inputChunk) {
                $inputCount += count($inputChunk);
                $remainder = count($inputChunk) % $blockSize;
                if ($remainder != 0) {
                    $inputChunk = array_pad($inputChunk, count($inputChunk) + (16 - $remainder), 0);
                }

                $iv = CryptoHelper::createIV($hashAlgorithm, $saltValue, $blockSize, $i);
                $outputChunk = CryptoHelper::crypt(true, $cipherAlgorithm, $cipherChaining, $key, $iv, $inputChunk);

                file_put_contents($tmpOutputChunk, pack('C*', ...$outputChunk), FILE_APPEND);
                unset($inputChunk, $outputChunk, $iv);
            }

            file_put_contents($tmpFileHeaderLength, pack('C*', ...CryptoHelper::createUInt32LEBuffer($inputCount, EncryptionConfig::PACKAGE_OFFSET)));
            file_put_contents($tmpFile, file_get_contents($tmpFileHeaderLength) . file_get_contents($tmpOutputChunk));

            unlink($tmpOutputChunk);
            unlink($tmpFileHeaderLength);

            return ['tmpFile' => $tmpFile];
        }

        return [];
    }
}