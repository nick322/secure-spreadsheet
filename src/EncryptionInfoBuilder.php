<?php

namespace Nick\SecureSpreadsheet;

use SimpleXMLElement;

class EncryptionInfoBuilder
{
    private const ENCRYPTION_INFO_PREFIX = [0x04, 0x00, 0x04, 0x00, 0x40, 0x00, 0x00, 0x00];

    public static function build(array $encryptionInfo)
    {
        $encryptionInfoNode = [
            'name' => 'encryption',
            'attributes' => [
                'xmlns' => 'http://schemas.microsoft.com/office/2006/encryption',
                'xmlns:p' => 'http://schemas.microsoft.com/office/2006/keyEncryptor/password',
                'xmlns:c' => 'http://schemas.microsoft.com/office/2006/keyEncryptor/certificate',
            ],
            'children' => [
                [
                    'name' => 'keyData',
                    'attributes' => [
                        'saltSize' => count($encryptionInfo['package']['saltValue']),
                        'blockSize' => $encryptionInfo['package']['blockSize'],
                        'keyBits' => $encryptionInfo['package']['keyBits'],
                        'hashSize' => $encryptionInfo['package']['hashSize'],
                        'cipherAlgorithm' => $encryptionInfo['package']['cipherAlgorithm'],
                        'cipherChaining' => $encryptionInfo['package']['cipherChaining'],
                        'hashAlgorithm' => $encryptionInfo['package']['hashAlgorithm'],
                        'saltValue' => base64_encode(pack('C*', ...$encryptionInfo['package']['saltValue'])),
                    ],
                ],
                [
                    'name' => 'dataIntegrity',
                    'attributes' => [
                        'encryptedHmacKey' => base64_encode(pack('C*', ...$encryptionInfo['dataIntegrity']['encryptedHmacKey'])),
                        'encryptedHmacValue' => base64_encode(pack('C*', ...$encryptionInfo['dataIntegrity']['encryptedHmacValue'])),
                    ],
                ],
                [
                    'name' => 'keyEncryptors',
                    'children' => [
                        [
                            'name' => 'keyEncryptor',
                            'attributes' => [
                                'uri' => 'http://schemas.microsoft.com/office/2006/keyEncryptor/password',
                            ],
                            'children' => [
                                [
                                    'name' => 'p:encryptedKey',
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
                                        'encryptedKeyValue' => base64_encode(pack('C*', ...$encryptionInfo['key']['encryptedKeyValue'])),
                                    ],
                                ],
                            ],
                        ],
                    ],
                ],
            ],
        ];

        $byte_array = unpack('C*', self::arrayToXml($encryptionInfoNode));
        array_unshift($byte_array, ...self::ENCRYPTION_INFO_PREFIX);

        return $byte_array;
    }

    private static function arrayToXml(array $array)
    {
        $rootNode = new SimpleXMLElement('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><encryption/>');
        self::buildXml($array, $rootNode);
        return str_replace(['\r', '\n', '\r\n', '\n\r'], '', $rootNode->asXML());
    }

    private static function buildXml(array $data, SimpleXMLElement $rootNode)
    {
        foreach ($data as $k => $v) {
            if (is_countable($v)) {
                foreach ($v as $kk => $vv) {
                    if ($k === 'attributes') {
                        $is_namespace = count(explode(':', $kk)) == 2;
                        if ($is_namespace) {
                            $rootNode->addAttribute('xmlns:xmlns:' . explode(':', $kk)[1], $vv);
                        } else {
                            $rootNode->addAttribute($kk, $vv);
                        }
                    }
                    if ($k === 'children') {
                        $is_namespace = count(explode(':', $vv['name'])) == 2;
                        if ($is_namespace) {
                            $r = $rootNode->addChild('xmlns:' . $vv['name'], '');
                        } else {
                            $r = $rootNode->addChild($vv['name'], '');
                        }
                        self::buildXml($vv, $r);
                    }
                }
            }
        }
    }
}