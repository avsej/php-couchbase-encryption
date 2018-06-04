<?php
/*
 * Copyright (c) 2018 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

namespace Couchbase\Tests;

use Couchbase\Aes256HmacSha256Provider;
use Couchbase\KeyProvider;
use Couchbase\Cluster;
use Couchbase\Bucket;

use PHPUnit_Framework_TestCase;

final class InsecureKeyProvider implements KeyProvider
{
    public function getKey(string $id)
    {
        switch ($id) {
            case 'mypublickey':
                return "!mysecretkey#9^5usdk39d&dlf)03sL";
            case 'HMAC_KEY_ID':
                return 'myauthpassword';
            default:
                throw new InvalidArgumentException("Unknown key '$id");
        }
    }
}

final class Aes256HmacSha256ProviderTest extends PHPUnit_Framework_TestCase
{
    private $cluster = null;
    private $bucket = null;

    protected function setUp()
    {
        $this->cluster = new Cluster('couchbase://localhost');
        $this->cluster->authenticateAs('Administrator', 'password');
        $this->bucket = $this->cluster->openBucket('default');
        $this->bucket->registerCryptoProvider(
            'AES-256-HMAC-SHA256',
            new Aes256HmacSha256Provider(new InsecureKeyProvider(), 'mypublickey', "HMAC_KEY_ID")
        );
    }

    protected function storeEncrypted(string $id, $payload, array $options)
    {
        $document = ['message' => $payload];
        $encrypted = $this->bucket->encryptFields($document, $options);
        $this->bucket->upsert($id, $encrypted);
    }

    protected function getEncrypted(string $id, array $options)
    {
        $encrypted = $this->bucket->get($id);
        $this->assertNotNull($encrypted->value, 'document should not be null');
        $document = $this->bucket->decryptFields($encrypted->value, $options);
        $this->assertArrayHasKey('message', $document);
        return $document['message'];
    }

    public function testEncryptDecrypt()
    {
        $fieldOptions = [
            [
                'name' => 'message',
                'alg' => 'AES-256-HMAC-SHA256'
            ]
        ];

        $this->storeEncrypted(
            'secret-1',
            'The old grey goose jumped over the wrickety gate.',
            $fieldOptions
        );
        $this->assertEquals(
            'The old grey goose jumped over the wrickety gate.',
            $this->getEncrypted('secret-1', $fieldOptions)
        );

        $this->storeEncrypted('secret-2', 10, $fieldOptions);
        $this->assertEquals(10, $this->getEncrypted('secret-2', $fieldOptions));

        $this->storeEncrypted('secret-3', '10', $fieldOptions);
        $this->assertEquals('10', $this->getEncrypted('secret-3', $fieldOptions));

        $this->storeEncrypted(
            'secret-4',
            ["The", "Old", "Grey","Goose", "Jumped", "over", "the", "wrickety", "gate"],
            $fieldOptions
        );
        $this->assertEquals(
            ["The", "Old", "Grey","Goose", "Jumped", "over", "the", "wrickety", "gate"],
            $this->getEncrypted('secret-4', $fieldOptions)
        );

        $this->storeEncrypted(
            'secret-5',
            [
               'myValue' => 'The old grey goose jumped over the wrickety gate.',
               'myInt' => 10
            ],
            $fieldOptions
        );
        $this->assertEquals(
            [
               'myValue' => 'The old grey goose jumped over the wrickety gate.',
               'myInt' => 10
            ],
            $this->getEncrypted('secret-5', $fieldOptions)
        );
    }
}
