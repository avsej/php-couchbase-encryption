<?php
/*
 * Copyright (c) 2018 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

namespace Couchbase\Tests;

use Couchbase\Rsa2048OaepSha1Provider;
use Couchbase\KeyProvider;
use Couchbase\Cluster;
use Couchbase\Bucket;

use PHPUnit_Framework_TestCase;

final class InsecureRSAKeyProvider implements KeyProvider
{
    public function getKey(string $id)
    {
        switch ($id) {
            case 'MyPublicKeyName':
                return <<<EOK
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwP6s/siq+geZAcN858as
1U6VIFeNDjvepl88jyd748idDt1ahDqw7pGw5WMygq04anWQG3kKUUhElxwG9BJ/
z4rxJXO0Vbflv0whgBlTVVxXuXSPwtyA200CENLO6aTaVN/aettSvA3cEuTit6eg
4Ayi0iSO97SI/9Jp4XeI4bA5Ls551Y9XR+PVbnaNgDWxGvebpw9GvjeK/hUdMHwP
8QhLdyLLjbQ6i3YxOWFYWqjtSQavCdkpHNui7U1rULxYYFSAhR64dOwoTs2yB8lL
MQsjTdIQR6oQZgaKRlVzPzHlJgp0tISJxvJYXrct7ZEjEFtTLnOMx4E7MbmcN3bs
DwIDAQAB
-----END PUBLIC KEY-----
EOK;
            case 'MyPrivateKeyName':
                return <<<EOK
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwP6s/siq+geZAcN858as1U6VIFeNDjvepl88jyd748idDt1a
hDqw7pGw5WMygq04anWQG3kKUUhElxwG9BJ/z4rxJXO0Vbflv0whgBlTVVxXuXSP
wtyA200CENLO6aTaVN/aettSvA3cEuTit6eg4Ayi0iSO97SI/9Jp4XeI4bA5Ls55
1Y9XR+PVbnaNgDWxGvebpw9GvjeK/hUdMHwP8QhLdyLLjbQ6i3YxOWFYWqjtSQav
CdkpHNui7U1rULxYYFSAhR64dOwoTs2yB8lLMQsjTdIQR6oQZgaKRlVzPzHlJgp0
tISJxvJYXrct7ZEjEFtTLnOMx4E7MbmcN3bsDwIDAQABAoIBAGiiq5CHo4tjyyUV
pAbVxKbxsBCU5zksZI63W9IRii35eo2wnX7Lg1oVS19S5PPMjqXJj5QVj+55zBZR
b8Oss/cGUbAIh2FiDwIkeJVHJdNF+ZnnBHqVqpc7rT8JzH0IkAcsRvwNJVIoAYWM
6w6/p41RzIU6pPjPvOdWYWmIsYIKZAhVnTf8QXDBpBdjzrrlTnocChNtEdkqyCFm
FILOWUiFbzWsHJe5/1o+v+Kw4qQGHNZVpFi2vQCJxTLdEbcUHCmVqgQOs+1hs+Ax
37pkXfVBRh97E5RV0Os8JtH3smw9uCcQveJanmuPVhsa+8zjOK2j1AHjdsaPZgMP
wuleVoECgYEA5mJ72lPRcFjNTTDQfLUHxCq4rWekkS+QsgPyBuE8z5mi7SsHuScV
i+PcLehRY8e6Z464Kl9Ni6c17HcM+Bm8ay70hxPeTlqrVBjxKiTixF1BccbBHPjd
Jl0WCEODxKMp5TAasJsfM7Pg18cYNakmOqK/agc7LJtsyo99jKfFYR8CgYEA1nPz
mGfhZZ2JXsNBNlqyvitV7Uzwa62DMGJUuosODnaz5v4gTPZhMF4gaOwh3wofP882
JZM1YEDF64Nn3tMDXImidoE9tKDMPyT1+obaBEPe8AfhAJGfMrWHgU3Yicd16bxK
vbU3kODpFgBtnE50JcceEyFYTWzZeNRWlsW4ZxECgYEAqTxDGthji5HQDhoDrPgW
omV3j/oIi5ZTRlFbou4mC6IiavInFD2/uClD/n0f/JolNhlC8+1aO3IzTGcPodjV
7i5p9igEL66vGHHSBlFeOzz97CRCi5PMcHgEzUE7NGFfTzqNAJqSyxoh2qAoCpMc
wAn5blutflEWE55gbch4V6UCgYEArFiBU2FgzmZd6O9ocENR1O1E4DHuIctPXEoa
J9TrFgqlqCVhVhjHoLR0vX3P9szOslxX+riks9c6eHyhtHzG/c6K50wUiB6WJsUQ
fidz/OuCtkrOs8NUOs+SuAMU3B2VkKPHOVDy+BcYm5r6fBy80UOF0wAAVDD/UVDs
ybza5tECgYB+ksZiUbZ+8WTXVIB3HJJT8U8bZ8676lrRUJ5YxB+avHh4g/TI+e53
jZKBVvB3Mhp6QFMZITuUTRgiGuAjBap4SZ32Pmyu3TxiWDxKktmvFMPLUVFntDJ0
th2u9Xpw8+T01AOCFc0PKtC8g0Covxu+qWLfqnJnTCx+Q03+dQj9rQ==
-----END RSA PRIVATE KEY-----
EOK;
            default:
                throw new InvalidArgumentException("Unknown key '$id");
        }
    }
}

final class Rsa2048OaepSha1ProviderTest extends PHPUnit_Framework_TestCase
{
    private $cluster = null;
    private $bucket = null;

    protected function setUp()
    {
        $this->cluster = new Cluster('couchbase://localhost');
        $this->cluster->authenticateAs('Administrator', 'password');
        $this->bucket = $this->cluster->openBucket('default');
        $this->bucket->registerCryptoProvider(
            'RSA-2048-OAEP-SHA1',
            new Rsa2048OaepSha1Provider(new InsecureRSAKeyProvider(), 'MyPublicKeyName', "MyPrivateKeyName")
        );

        $tmp = new Rsa2048OaepSha1Provider(new InsecureRSAKeyProvider(), 'MyPublicKeyName', "MyPrivateKeyName");
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
                'alg' => 'RSA-2048-OAEP-SHA1'
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
