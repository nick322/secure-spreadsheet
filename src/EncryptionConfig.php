<?php

namespace Nick\SecureSpreadsheet;

class EncryptionConfig
{
    public const PACKAGE_OFFSET = 8;
    public const PACKAGE_ENCRYPTION_CHUNK_SIZE = 4096;
    
    public const BLOCK_KEYS = [
        'dataIntegrity' => [
            'hmacKey' => [0x5F, 0xB2, 0xAD, 0x01, 0x0C, 0xB9, 0xE1, 0xF6],
            'hmacValue' => [0xA0, 0x67, 0x7F, 0x02, 0xB2, 0x2C, 0x84, 0x33],
        ],
        'key' => [0x14, 0x6E, 0x0B, 0xE7, 0xAB, 0xAC, 0xD0, 0xD6],
        'verifierHash' => [
            'input' => [0xFE, 0xA7, 0xD2, 0x76, 0x3B, 0x4B, 0x9E, 0x79],
            'value' => [0xD7, 0xAA, 0x0F, 0x6D, 0x30, 0x61, 0x34, 0x4E],
        ],
    ];

    public static function getDefaultEncryptionInfo(array $packageKey)
    {
        return [
            'package' => [
                'cipherAlgorithm' => 'AES',
                'cipherChaining' => 'ChainingModeCBC',
                'saltValue' => unpack('C*', random_bytes(16)),
                'hashAlgorithm' => 'SHA512',
                'hashSize' => 64,
                'blockSize' => 16,
                'keyBits' => count($packageKey) * 8,
            ],
            'key' => [
                'cipherAlgorithm' => 'AES',
                'cipherChaining' => 'ChainingModeCBC',
                'saltValue' => unpack('C*', random_bytes(16)),
                'hashAlgorithm' => 'SHA512',
                'hashSize' => 64,
                'blockSize' => 16,
                'spinCount' => 100000,
                'keyBits' => 256,
            ],
        ];
    }
}