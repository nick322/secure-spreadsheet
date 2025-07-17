<?php

namespace Nick\SecureSpreadsheet;

use Exception;

class CryptoHelper
{
    public static function crypt(bool $encrypt, string $cipherAlgorithm, string $cipherChaining, array $key, array $iv, array $input)
    {
        $algorithm = strtolower($cipherAlgorithm) . '-' . (count($key) * 8);

        if ($cipherChaining === 'ChainingModeCBC') {
            $algorithm .= '-cbc';
        } else {
            throw new Exception("Unknown cipher chaining: $cipherChaining");
        }

        if ($encrypt) {
            $ciphertext = openssl_encrypt(
                pack('C*', ...$input),
                $algorithm,
                pack('C*', ...$key),
                OPENSSL_NO_PADDING,
                pack('C*', ...$iv)
            );
            return unpack('C*', $ciphertext);
        }

        return [];
    }

    public static function hash(string $algorithm, array ...$buffers)
    {
        $algorithm = strtolower($algorithm);
        $buffers = array_merge([], ...$buffers);

        if (!in_array($algorithm, hash_algos())) {
            throw new Exception("Hash algorithm '$algorithm' not supported!");
        }

        $ctx = hash_init($algorithm);
        hash_update($ctx, pack('C*', ...$buffers));

        return unpack('C*', hash_final($ctx, true));
    }

    public static function hmac(string $algorithm, array $key, string $fileName)
    {
        return unpack('C*', hash_hmac_file(
            strtolower($algorithm),
            $fileName,
            pack('C*', ...$key),
            true
        ));
    }

    public static function createUInt32LEBuffer(int $value, int $bufferSize = 4)
    {
        return array_pad(array_values(unpack('C*', pack('V', $value))), $bufferSize, 0);
    }

    public static function convertPasswordToKey(string $password, string $hashAlgorithm, array $saltValue, int $spinCount, int $keyBits, array $blockKey)
    {
        $passwordBuffer = array_map('hexdec', str_split(bin2hex(mb_convert_encoding($password, 'UTF-16LE', 'utf-8')), 2));
        $key = self::hash($hashAlgorithm, $saltValue, $passwordBuffer);

        $algo = strtolower($hashAlgorithm);
        $bKey = pack('C*', ...$key);

        for ($i = 0; $i < $spinCount; $i++) {
            $bKey = hash($algo, pack('V', $i) . $bKey, true);
        }

        $key = unpack('C*', $bKey);
        $key = self::hash($hashAlgorithm, $key, $blockKey);

        $keyBytes = $keyBits / 8;
        if (count($key) < $keyBytes) {
            $key = array_pad($key, $keyBytes, 0x36);
        } elseif (count($key) > $keyBytes) {
            $key = array_slice($key, 0, $keyBytes);
        }

        return $key;
    }

    public static function createIV(string $hashAlgorithm, array $saltValue, int $blockSize, $blockKey)
    {
        if (is_int($blockKey)) {
            $blockKey = self::createUInt32LEBuffer($blockKey);
        }

        $iv = self::hash($hashAlgorithm, $saltValue, $blockKey);
        if (count($iv) < $blockSize) {
            $iv = array_pad($iv, $blockSize, 0x36);
        } elseif (count($iv) > $blockSize) {
            $iv = array_slice($iv, 0, $blockSize);
        }

        return $iv;
    }
}