<?php

namespace Nick\SecureSpreadsheet;

use Exception;
use OLE;
use OLE_PPS_File;
use OLE_PPS_Root;

class Encrypt
{
    private $data;
    private $password;
    private $noFile = false;

    public function __construct(bool $nofile = false)
    {
        $this->noFile = $nofile;
    }

    public function input(string $data)
    {
        if ($this->noFile) {
            $this->data = function () use ($data) {
                for ($i = 0; $i < strlen($data) / 4096; $i++) {
                    yield unpack('C*', substr($data, $i * 4096, 4096));
                }
            };
        } else {
            $this->data = function () use ($data) {
                $fp = fopen($data, 'rb');
                if (!$fp) {
                    throw new Exception('file not found');
                }
                while (!feof($fp)) {
                    yield unpack('C*', fread($fp, 4096));
                }
                fclose($fp);
            };
        }

        return $this;
    }

    public function password(string $password)
    {
        $this->password = $password;
        return $this;
    }

    public function output(?string $filePath = null)
    {
        if (!$this->noFile && is_null($filePath)) {
            throw new Exception('Output Filepath cannot be NULL when NOFILE is False');
        }

        $packageKey = unpack('C*', random_bytes(32));
        $encryptionInfo = EncryptionConfig::getDefaultEncryptionInfo($packageKey);

        $encryptedPackage = PackageEncryptor::encrypt(
            $encryptionInfo['package']['cipherAlgorithm'],
            $encryptionInfo['package']['cipherChaining'],
            $encryptionInfo['package']['hashAlgorithm'],
            $encryptionInfo['package']['blockSize'],
            $encryptionInfo['package']['saltValue'],
            $packageKey,
            $this->data
        );

        $encryptionInfo['dataIntegrity'] = $this->createDataIntegrity($encryptionInfo, $packageKey, $encryptedPackage['tmpFile']);

        $key = CryptoHelper::convertPasswordToKey(
            $this->password,
            $encryptionInfo['key']['hashAlgorithm'],
            $encryptionInfo['key']['saltValue'],
            $encryptionInfo['key']['spinCount'],
            $encryptionInfo['key']['keyBits'],
            EncryptionConfig::BLOCK_KEYS['key']
        );

        $encryptionInfo['key']['encryptedKeyValue'] = CryptoHelper::crypt(
            true,
            $encryptionInfo['key']['cipherAlgorithm'],
            $encryptionInfo['key']['cipherChaining'],
            $key,
            $encryptionInfo['key']['saltValue'],
            $packageKey
        );

        $this->addVerifierHash($encryptionInfo);

        $encryptionInfoBuffer = EncryptionInfoBuilder::build($encryptionInfo);

        $OLE = new OLE_PPS_File(OLE::Asc2Ucs('EncryptionInfo'));
        $OLE->init();
        $OLE->append(pack('C*', ...$encryptionInfoBuffer));

        $OLE2 = new OLE_PPS_File(OLE::Asc2Ucs('EncryptedPackage'));
        $OLE2->init();
        $filesize = filesize($encryptedPackage['tmpFile']);
        for ($i = 0; $i < ($filesize / 4096); $i++) {
            $unpackEncryptedPackage = unpack('C*', file_get_contents($encryptedPackage['tmpFile'], false, null, $i * 4096, 4096));
            $OLE2->append(pack('C*', ...$unpackEncryptedPackage));
        }

        unlink($encryptedPackage['tmpFile']);

        $root = new OLE_PPS_Root(1000000000, 1000000000, [$OLE, $OLE2]);

        if ($this->noFile) {
            $filePath = tempnam(sys_get_temp_dir(), 'NOFILE');
        }

        $root->save($filePath);

        return file_get_contents($filePath);
    }

    private function createDataIntegrity(array $encryptionInfo, array $packageKey, string $tmpFile)
    {
        $hmacKey = unpack('C*', random_bytes(64));
        $hmacKeyIV = CryptoHelper::createIV(
            $encryptionInfo['package']['hashAlgorithm'],
            $encryptionInfo['package']['saltValue'],
            $encryptionInfo['package']['blockSize'],
            EncryptionConfig::BLOCK_KEYS['dataIntegrity']['hmacKey']
        );

        $encryptedHmacKey = CryptoHelper::crypt(
            true,
            $encryptionInfo['package']['cipherAlgorithm'],
            $encryptionInfo['package']['cipherChaining'],
            $packageKey,
            $hmacKeyIV,
            $hmacKey
        );

        $hmacValue = CryptoHelper::hmac($encryptionInfo['package']['hashAlgorithm'], $hmacKey, $tmpFile);

        $hmacValueIV = CryptoHelper::createIV(
            $encryptionInfo['package']['hashAlgorithm'],
            $encryptionInfo['package']['saltValue'],
            $encryptionInfo['package']['blockSize'],
            EncryptionConfig::BLOCK_KEYS['dataIntegrity']['hmacValue']
        );

        $encryptedHmacValue = CryptoHelper::crypt(
            true,
            $encryptionInfo['package']['cipherAlgorithm'],
            $encryptionInfo['package']['cipherChaining'],
            $packageKey,
            $hmacValueIV,
            $hmacValue
        );

        return [
            'encryptedHmacKey' => $encryptedHmacKey,
            'encryptedHmacValue' => $encryptedHmacValue,
        ];
    }

    private function addVerifierHash(array &$encryptionInfo)
    {
        $verifierHashInput = unpack('C*', random_bytes(16));

        $verifierHashInputKey = CryptoHelper::convertPasswordToKey(
            $this->password,
            $encryptionInfo['key']['hashAlgorithm'],
            $encryptionInfo['key']['saltValue'],
            $encryptionInfo['key']['spinCount'],
            $encryptionInfo['key']['keyBits'],
            EncryptionConfig::BLOCK_KEYS['verifierHash']['input']
        );

        $encryptionInfo['key']['encryptedVerifierHashInput'] = CryptoHelper::crypt(
            true,
            $encryptionInfo['key']['cipherAlgorithm'],
            $encryptionInfo['key']['cipherChaining'],
            $verifierHashInputKey,
            $encryptionInfo['key']['saltValue'],
            $verifierHashInput
        );

        $verifierHashValue = CryptoHelper::hash($encryptionInfo['key']['hashAlgorithm'], $verifierHashInput);

        $verifierHashValueKey = CryptoHelper::convertPasswordToKey(
            $this->password,
            $encryptionInfo['key']['hashAlgorithm'],
            $encryptionInfo['key']['saltValue'],
            $encryptionInfo['key']['spinCount'],
            $encryptionInfo['key']['keyBits'],
            EncryptionConfig::BLOCK_KEYS['verifierHash']['value']
        );

        $encryptionInfo['key']['encryptedVerifierHashValue'] = CryptoHelper::crypt(
            true,
            $encryptionInfo['key']['cipherAlgorithm'],
            $encryptionInfo['key']['cipherChaining'],
            $verifierHashValueKey,
            $encryptionInfo['key']['saltValue'],
            $verifierHashValue
        );
    }
}