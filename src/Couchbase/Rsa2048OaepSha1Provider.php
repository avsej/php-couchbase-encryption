<?php
/*
 * Copyright (c) 2018 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

namespace Couchbase;

/**
 * Provides wrapper over openssl library for Couchbhase field encryption.
 *
 * Implements 'RSA-2048-OAEP-SHA1' cipher.
 */
class Rsa2048OaepSha1Provider extends CryptoProvider
{
    /**
     * @var KeyProvider the key provider
     */
    private $keyProvider;

    /**
     * @var string the key identifier for public part of the key
     */
    private $publicKeyId;

    /**
     * @var string the key identifier for private part of the key
     */
    private $privateKeyId;

    /**
     * Create instance of the OpenSSL crypto provider
     *
     * @param KeyProvider the key provider
     */
    public function __construct(KeyProvider $keyProvider, string $publicKeyId, string $privateKeyId)
    {
        $this->keyProvider = $keyProvider;
        $this->publicKeyId = $publicKeyId;
        $this->privateKeyId = $privateKeyId;
    }

    public function getKeyId()
    {
        return $this->publicKeyId;
    }

    public function encrypt(string $bytes, string $iv = null)
    {
        $encrypted = NULL;
        openssl_public_encrypt($bytes, $encrypted, $this->keyProvider->getKey($this->publicKeyId),
                               OPENSSL_PKCS1_OAEP_PADDING);
        return $encrypted;
    }

    public function decrypt(string $bytes, string $iv = null)
    {
        $decrypted = NULL;
        $rv = openssl_private_decrypt($bytes, $decrypted, $this->keyProvider->getKey($this->privateKeyId),
                                      OPENSSL_PKCS1_OAEP_PADDING);
        return $decrypted;
    }
};
