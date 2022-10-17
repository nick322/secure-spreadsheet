<?php

namespace Nick\SecureSpreadsheet;

use Exception;

class Encrypt
{
    public $data;
    public $password;
    public $NOFILE = false;
    public $PACKAGE_OFFSET = 8;
    public $PACKAGE_ENCRYPTION_CHUNK_SIZE = 4096;
    public $BLOCK_KEYS = [
        'dataIntegrity' => [
            'hmacKey' => [0x5f, 0xb2, 0xad, 0x01, 0x0c, 0xb9, 0xe1, 0xf6],
            'hmacValue' => [0xa0, 0x67, 0x7f, 0x02, 0xb2, 0x2c, 0x84, 0x33],
        ],
        'key' => [0x14, 0x6e, 0x0b, 0xe7, 0xab, 0xac, 0xd0, 0xd6],
        'verifierHash' => [
            'input' => [0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79],
            'value' => [0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e],
        ]
    ];

    public function __construct(bool $nofile = false)
    {
        $this->NOFILE = $nofile;
    }

    public function input(string $data)
    {
        if ($this->NOFILE) {
            $this->data = unpack("C*", $data);
            return $this;
        }

        $fp = fopen($data, 'rb');
        $binary = fread($fp, filesize($data));
        fclose($fp);
        $this->data = unpack("C*", $binary);
        return $this;
    }

    public function password(string $password)
    {
        $this->password = $password;
        return $this;
    }

    public function output(string $filePath = null)
    {
        if (!$this->NOFILE && is_null($filePath)) {
            throw new Exception("Output Filepath cannot be NULL when NOFILE is False");
        }
        
        $packageKey = unpack('C*', random_bytes(32));
        $encryptionInfo = [
            'package' => [
                'cipherAlgorithm' => 'AES', // Cipher algorithm to use. Excel uses AES.
                'cipherChaining' => 'ChainingModeCBC', // Cipher chaining mode to use. Excel uses CBC.
                'saltValue' => unpack('C*', random_bytes(16)), // Random value to use as encryption salt. Excel uses 16 bytes.
                'hashAlgorithm' => 'SHA512', // Hash algorithm to use. Excel uses SHA512.
                'hashSize' => 64, // The size of the hash in bytes. SHA512 results in 64-byte hashes
                'blockSize' => 16, // The number of bytes used to encrypt one block of data. It MUST be at least 2, no greater than 4096, and a multiple of 2. Excel uses 16
                'keyBits' => count($packageKey) * 8
            ],
            'key' => [ // Info on the encryption of the package key.
                'cipherAlgorithm' => 'AES', // Cipher algorithm to use. Excel uses AES.
                'cipherChaining' => 'ChainingModeCBC', // Cipher chaining mode to use. Excel uses CBC.
                'saltValue' => unpack('C*', random_bytes(16)), // Random value to use as encryption salt. Excel uses 16 bytes.
                'hashAlgorithm' => 'SHA512', // Hash algorithm to use. Excel uses SHA512.
                'hashSize' => 64, // The size of the hash in bytes. SHA512 results in 64-byte hashes
                'blockSize' => 16, // The number of bytes used to encrypt one block of data. It MUST be at least 2, no greater than 4096, and a multiple of 2. Excel uses 16
                'spinCount' => 100000, // The number of times to iterate on a hash of a password. It MUST NOT be greater than 10,000,000. Excel uses 100,000.
                'keyBits' => 256 // The length of the key to generate from the password. Must be a multiple of 8. Excel uses 256.
            ]
        ];

        /* Package Encryption */
        $encryptedPackage = $this->_cryptPackage(
            true,
            $encryptionInfo['package']['cipherAlgorithm'],
            $encryptionInfo['package']['cipherChaining'],
            $encryptionInfo['package']['hashAlgorithm'],
            $encryptionInfo['package']['blockSize'],
            $encryptionInfo['package']['saltValue'],
            $packageKey,
            $this->data
        );
        /* Data Integrity */

        // Create the data integrity fields used by clients for integrity checks.
        // First generate a random array of bytes to use in HMAC. The docs say to use the same length as the key salt, but Excel seems to use 64.
        $hmacKey = unpack('C*', random_bytes(64));
        // Then create an initialization vector using the package encryption info and the appropriate block key.
        $hmacKeyIV = $this->_createIV(
            $encryptionInfo['package']['hashAlgorithm'],
            $encryptionInfo['package']['saltValue'],
            $encryptionInfo['package']['blockSize'],
            $this->BLOCK_KEYS['dataIntegrity']['hmacKey']
        );

        // Use the package key and the IV to encrypt the HMAC key
        $encryptedHmacKey = $this->_crypt(
            true,
            $encryptionInfo['package']['cipherAlgorithm'],
            $encryptionInfo['package']['cipherChaining'],
            $packageKey,
            $hmacKeyIV,
            $hmacKey
        );


        // Now create the HMAC
        $hmacValue = $this->_hmac($encryptionInfo['package']['hashAlgorithm'], $hmacKey, $encryptedPackage);

        // Next generate an initialization vector for encrypting the resulting HMAC value.
        $hmacValueIV = $this->_createIV(
            $encryptionInfo['package']['hashAlgorithm'],
            $encryptionInfo['package']['saltValue'],
            $encryptionInfo['package']['blockSize'],
            $this->BLOCK_KEYS['dataIntegrity']['hmacValue']
        );

        // Now encrypt the value
        $encryptedHmacValue = $this->_crypt(
            true,
            $encryptionInfo['package']['cipherAlgorithm'],
            $encryptionInfo['package']['cipherChaining'],
            $packageKey,
            $hmacValueIV,
            $hmacValue
        );

        // Put the encrypted key and value on the encryption info
        $encryptionInfo['dataIntegrity'] = [
            'encryptedHmacKey' => $encryptedHmacKey,
            'encryptedHmacValue' => $encryptedHmacValue
        ];

        /* Key Encryption */
        $password = $this->password;
        // Convert the password to an encryption key
        $key = $this->_convertPasswordToKey(
            $password,
            $encryptionInfo['key']['hashAlgorithm'],
            $encryptionInfo['key']['saltValue'],
            $encryptionInfo['key']['spinCount'],
            $encryptionInfo['key']['keyBits'],
            $this->BLOCK_KEYS['key']
        );

        // // Encrypt the package key with the
        $encryptionInfo['key']['encryptedKeyValue'] = $this->_crypt(
            true,
            $encryptionInfo['key']['cipherAlgorithm'],
            $encryptionInfo['key']['cipherChaining'],
            $key,
            $encryptionInfo['key']['saltValue'],
            $packageKey
        );

        /* Verifier hash */

        // Create a random byte array for hashing
        $verifierHashInput = random_bytes(16);
        $verifierHashInput = unpack('C*', $verifierHashInput);

        // Create an encryption key from the password for the input
        $verifierHashInputKey = $this->_convertPasswordToKey(
            $password,
            $encryptionInfo['key']['hashAlgorithm'],
            $encryptionInfo['key']['saltValue'],
            $encryptionInfo['key']['spinCount'],
            $encryptionInfo['key']['keyBits'],
            $this->BLOCK_KEYS['verifierHash']['input']
        );

        // Use the key to encrypt the verifier input
        $encryptionInfo['key']['encryptedVerifierHashInput'] = $this->_crypt(
            true,
            $encryptionInfo['key']['cipherAlgorithm'],
            $encryptionInfo['key']['cipherChaining'],
            $verifierHashInputKey,
            $encryptionInfo['key']['saltValue'],
            $verifierHashInput
        );


        // Create a hash of the input
        $verifierHashValue = $this->_hash($encryptionInfo['key']['hashAlgorithm'], $verifierHashInput);

        // Create an encryption key from the password for the hash
        $verifierHashValueKey = $this->_convertPasswordToKey(
            $password,
            $encryptionInfo['key']['hashAlgorithm'],
            $encryptionInfo['key']['saltValue'],
            $encryptionInfo['key']['spinCount'],
            $encryptionInfo['key']['keyBits'],
            $this->BLOCK_KEYS['verifierHash']['value']
        );

        // Use the key to encrypt the hash value
        $encryptionInfo['key']['encryptedVerifierHashValue'] = $this->_crypt(
            true,
            $encryptionInfo['key']['cipherAlgorithm'],
            $encryptionInfo['key']['cipherChaining'],
            $verifierHashValueKey,
            $encryptionInfo['key']['saltValue'],
            $verifierHashValue
        );

        // Build the encryption info buffer
        $encryptionInfoBuffer = $this->_buildEncryptionInfo($encryptionInfo);

        $CFB = new CFB();
        $output = $CFB->cfb_new(); // Add the encryption info and encrypted package

        $CFB->cfb_add($output, 'EncryptionInfo', $encryptionInfoBuffer);
        $CFB->cfb_add($output, 'EncryptedPackage', $encryptedPackage); // Delete the SheetJS entry that is added at initialization

        $output = $CFB->write($output); // The cfb library writes to a Uint8array in the browser. Convert to a Buffer.
        $output = pack('C*', ...$output);
        if ($this->NOFILE) {
            return $output;
        }

        file_put_contents($filePath, $output);
    }


    private function _buildEncryptionInfo($encryptionInfo)
    {
        $ENCRYPTION_INFO_PREFIX = [0x04, 0x00, 0x04, 0x00, 0x40, 0x00, 0x00, 0x00];

        // Map the object into the appropriate XML structure. Buffers are encoded in base 64.

        $encryptionInfoNode = [
            'name' => "encryption",
            'attributes' => [
                'xmlns' => "http://schemas.microsoft.com/office/2006/encryption",
                'xmlns:p' => "http://schemas.microsoft.com/office/2006/keyEncryptor/password",
                'xmlns:c' => "http://schemas.microsoft.com/office/2006/keyEncryptor/certificate"
            ],
            'children' => [
                [
                    'name' => "keyData",
                    'attributes' => [
                        'saltSize' => count($encryptionInfo['package']['saltValue']),
                        'blockSize' => $encryptionInfo['package']['blockSize'],
                        'keyBits' => $encryptionInfo['package']['keyBits'],
                        'hashSize' => $encryptionInfo['package']['hashSize'],
                        'cipherAlgorithm' => $encryptionInfo['package']['cipherAlgorithm'],
                        'cipherChaining' => $encryptionInfo['package']['cipherChaining'],
                        'hashAlgorithm' => $encryptionInfo['package']['hashAlgorithm'],
                        'saltValue' => base64_encode(pack('C*', ...$encryptionInfo['package']['saltValue'])),
                    ]
                ],
                [
                    'name' => "dataIntegrity",
                    'attributes' => [
                        'encryptedHmacKey' => base64_encode(pack('C*', ...$encryptionInfo['dataIntegrity']['encryptedHmacKey'])),
                        'encryptedHmacValue' => base64_encode(pack('C*', ...$encryptionInfo['dataIntegrity']['encryptedHmacValue']))
                    ]
                ],
                [
                    'name' => "keyEncryptors",
                    'children' => [
                        [
                            'name' => "keyEncryptor",
                            'attributes' => [
                                'uri' => "http://schemas.microsoft.com/office/2006/keyEncryptor/password"
                            ],
                            'children' => [
                                [
                                    'name' => "p:encryptedKey",
                                    'attributes' => [
                                        'spinCount' => $encryptionInfo['key']['spinCount'],
                                        'saltSize' => count($encryptionInfo['key']['saltValue']),
                                        'blockSize' => $encryptionInfo['key']['blockSize'],
                                        'keyBits' => $encryptionInfo['key']['keyBits'],
                                        'hashSize' => $encryptionInfo['key']['hashSize'],
                                        'cipherAlgorithm' => $encryptionInfo['key']['cipherAlgorithm'],
                                        'cipherChaining' => $encryptionInfo['key']['cipherChaining'],
                                        'hashAlgorithm' => $encryptionInfo['key']['hashAlgorithm'],
                                        'saltValue' => base64_encode(pack('C*', ...$encryptionInfo['key']['saltValue'])),
                                        'encryptedVerifierHashInput' => base64_encode(pack('C*', ...$encryptionInfo['key']['encryptedVerifierHashInput'])),
                                        'encryptedVerifierHashValue' => base64_encode(pack('C*', ...$encryptionInfo['key']['encryptedVerifierHashValue'])),
                                        'encryptedKeyValue' => base64_encode(pack('C*', ...$encryptionInfo['key']['encryptedKeyValue']))
                                    ]
                                ]
                            ]
                        ]
                    ]
                ]
            ]
        ];
        $byte_array = unpack('C*', $this->arrayToXml($encryptionInfoNode));

        array_unshift($byte_array, ...$ENCRYPTION_INFO_PREFIX);

        return $byte_array;
    }


    // Define a function that converts array to xml.
    private function arrayToXml($array)
    {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><encryption xmlns=\"http://schemas.microsoft.com/office/2006/encryption\" xmlns:p=\"http://schemas.microsoft.com/office/2006/keyEncryptor/password\" xmlns:c=\"http://schemas.microsoft.com/office/2006/keyEncryptor/certificate\"><keyData saltSize=\"{$array['children'][0]['attributes']['saltSize']}\" blockSize=\"{$array['children'][0]['attributes']['blockSize']}\" keyBits=\"{$array['children'][0]['attributes']['keyBits']}\" hashSize=\"{$array['children'][0]['attributes']['hashSize']}\" cipherAlgorithm=\"{$array['children'][0]['attributes']['cipherAlgorithm']}\" cipherChaining=\"{$array['children'][0]['attributes']['cipherChaining']}\" hashAlgorithm=\"{$array['children'][0]['attributes']['hashAlgorithm']}\" saltValue=\"{$array['children'][0]['attributes']['saltValue']}\"/><dataIntegrity encryptedHmacKey=\"{$array['children'][1]['attributes']['encryptedHmacKey']}\" encryptedHmacValue=\"{$array['children'][1]['attributes']['encryptedHmacValue']}\"/><keyEncryptors><keyEncryptor uri=\"http://schemas.microsoft.com/office/2006/keyEncryptor/password\"><p:encryptedKey spinCount=\"{$array['children'][2]['children'][0]['children'][0]['attributes']['spinCount']}\" saltSize=\"{$array['children'][2]['children'][0]['children'][0]['attributes']['saltSize']}\" blockSize=\"{$array['children'][2]['children'][0]['children'][0]['attributes']['blockSize']}\" keyBits=\"{$array['children'][2]['children'][0]['children'][0]['attributes']['keyBits']}\" hashSize=\"{$array['children'][2]['children'][0]['children'][0]['attributes']['hashSize']}\" cipherAlgorithm=\"{$array['children'][2]['children'][0]['children'][0]['attributes']['cipherAlgorithm']}\" cipherChaining=\"{$array['children'][2]['children'][0]['children'][0]['attributes']['cipherChaining']}\" hashAlgorithm=\"{$array['children'][2]['children'][0]['children'][0]['attributes']['hashAlgorithm']}\" saltValue=\"{$array['children'][2]['children'][0]['children'][0]['attributes']['saltValue']}\" encryptedVerifierHashInput=\"{$array['children'][2]['children'][0]['children'][0]['attributes']['encryptedVerifierHashInput']}\" encryptedVerifierHashValue=\"{$array['children'][2]['children'][0]['children'][0]['attributes']['encryptedVerifierHashValue']}\" encryptedKeyValue=\"{$array['children'][2]['children'][0]['children'][0]['attributes']['encryptedKeyValue']}\"/></keyEncryptor></keyEncryptors></encryption>";
    }


    private function _crypt($encrypt, $cipherAlgorithm, $cipherChaining, $key, $iv, $input)
    {
        $algorithm = strtolower($cipherAlgorithm) . '-' . (count($key) * 8);

        if ($cipherChaining === 'ChainingModeCBC') $algorithm .= '-cbc';
        else throw new \Exception("Unknown cipher chaining: $cipherChaining");

        if ($encrypt) {
            $ciphertext = openssl_encrypt(
                pack('C*', ...$input),
                $algorithm,
                pack('C*', ...$key),
                OPENSSL_NO_PADDING,
                pack('C*', ...$iv)
            );
            $cipher = unpack('C*', $ciphertext);
        }
        return $cipher;
    }

    private function _hash($algorithm, ...$buffers)
    {
        $algorithm = strtolower($algorithm);

        $buffers = array_merge([], ...$buffers);

        if (!in_array($algorithm, hash_algos())) throw new \Exception("Hash algorithm '$algorithm' not supported!");

        $ctx = hash_init($algorithm);

        hash_update($ctx, pack('C*', ...$buffers));
        return unpack('C*', hash_final($ctx, true));
    }

    private function _hmac($algorithm, $key, ...$buffers)
    {
        $algorithm = strtolower($algorithm);
        $key = pack('C*', ...$key);

        if (!in_array($algorithm, hash_hmac_algos())) throw new \Exception("HMAC algorithm '$algorithm' not supported!");

        $ctx = hash_init($algorithm, HASH_HMAC, $key);

        $buffers = array_merge([], ...$buffers);
        hash_update($ctx, pack('C*', ...$buffers));
        return unpack('C*', hash_final($ctx, true));
    }

    private function _createUInt32LEBuffer($value, $bufferSize = 4)
    {
        if ((strlen($a = dechex($value))) % 2 != 0) {
            $a = '0' . $a;
        }
        $buffer = array_map('hexdec', array_reverse(str_split($a, 2)));
        $buffer = array_pad($buffer, $bufferSize, (int) 0);
        return $buffer;
    }

    private function _convertPasswordToKey($password, $hashAlgorithm, $saltValue, $spinCount, $keyBits, $blockKey)
    {
        // Password must be in unicode buffer
        $passwordBuffer = array_map('hexdec', str_split(bin2hex(mb_convert_encoding($password,  "UTF-16LE", "utf-8")), 2));
        // Generate the initial hash
        $key = $this->_hash($hashAlgorithm, $saltValue, $passwordBuffer);

        // Now regenerate until spin count
        for ($i = 0; $i < $spinCount; $i++) {
            $iterator = $this->_createUInt32LEBuffer($i);
            $key = $this->_hash($hashAlgorithm, $iterator, $key);
        }

        // Now generate the final hash
        $key = $this->_hash($hashAlgorithm, $key, $blockKey);

        // Truncate or pad as needed to get to length of keyBits
        $keyBytes = $keyBits / 8;
        if (count($key) < $keyBytes) {
            $key = array_pad($key, $keyBytes, 0x36);
        } else if (count($key) > $keyBytes) {
            $key = array_slice($key, 0, $keyBytes);
        }

        return $key;
    }

    private function _createIV($hashAlgorithm, $saltValue, $blockSize, $blockKey)
    {
        // Create the block key from the current index
        if (is_int($blockKey)) $blockKey = $this->_createUInt32LEBuffer($blockKey);

        // Create the initialization vector by hashing the salt with the block key.
        // Truncate or pad as needed to meet the block size.
        $iv = $this->_hash($hashAlgorithm, $saltValue, $blockKey);
        if (count($iv) < $blockSize) {
            $iv = array_pad($iv, $blockSize, 0x36);
        } else if (count($iv) > $blockSize) {
            $iv = array_slice($iv, 0, $blockSize);
        }

        return $iv;
    }

    private function _cryptPackage(
        $encrypt,
        $cipherAlgorithm,
        $cipherChaining,
        $hashAlgorithm,
        $blockSize,
        $saltValue,
        $key,
        $input
    ) {

        // The first 8 bytes is supposed to be the length, but it seems like it is really the length - 4..
        $outputChunks = [];

        // The package is encoded in chunks. Encrypt/decrypt each and concat.
        $i = 0;
        $start = 0;
        $end = 0;

        while ($end < count($input)) {
            $start = $end;
            $end = $start + $this->PACKAGE_ENCRYPTION_CHUNK_SIZE;
            if ($end > count($input)) $end = count($input);

            // Grab the next chunk
            $inputChunk = array_slice($input, $start, $this->PACKAGE_ENCRYPTION_CHUNK_SIZE);

            // Pad the chunk if it is not an integer multiple of the block size
            $remainder = count($inputChunk) % $blockSize;
            if ($remainder != 0) $inputChunk = array_pad($inputChunk, count($inputChunk) + (16 - $remainder), 0);
            // Create the initialization vector
            $iv = $this->_createIV($hashAlgorithm, $saltValue, $blockSize, $i);

            // Encrypt/decrypt the chunk and add it to the array
            $outputChunk = $this->_crypt($encrypt, $cipherAlgorithm, $cipherChaining, $key, $iv, $inputChunk);
            $outputChunks[] = $outputChunk;

            $i++;
        }

        // Concat all of the output chunks.
        $output = array_merge([], ...$outputChunks);

        if ($encrypt) {
            // Put the length of the package in the first 8 bytes
            $output = array_merge($this->_createUInt32LEBuffer(count($input), $this->PACKAGE_OFFSET), $output);
        }

        return $output;
    }
}
