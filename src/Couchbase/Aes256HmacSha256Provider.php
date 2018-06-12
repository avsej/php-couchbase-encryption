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
 * Implements 'AES-256-HMAC-SHA256' cipher.
 */
class Aes256HmacSha256Provider extends CryptoProvider
{
    /**
     * @var KeyProvider the key provider
     */
    private $keyProvider;

    /**
     * @var string the key identifier for HMAC signature
     */
    private $hmacKeyId;

    /**
     * Create instance of the OpenSSL crypto provider
     *
     * @param KeyProvider the key provider
     */
    public function __construct(KeyProvider $keyProvider, string $keyId, string $hmacKeyId)
    {
        $this->keyProvider = $keyProvider;
        $this->keyId = $keyId;
        $this->hmacKeyId = $hmacKeyId;
    }

    public function getKeyId()
    {
        return $this->keyId;
    }

    public function generateIV()
    {
        return openssl_random_pseudo_bytes(16);
    }

    public function encrypt(string $bytes, string $iv = null)
    {
        return openssl_encrypt($bytes, 'AES-256-CBC', $this->keyProvider->getKey($this->keyId), OPENSSL_RAW_DATA, $iv);
    }

    public function decrypt(string $bytes, string $iv = null)
    {
        return openssl_decrypt($bytes, 'AES-256-CBC', $this->keyProvider->getKey($this->keyId), OPENSSL_RAW_DATA, $iv);
    }

    public function sign(array $bytes)
    {
        $ctx = hash_init('sha256', HASH_HMAC, $this->keyProvider->getKey($this->hmacKeyId));
        foreach ($bytes as $chunk) {
            hash_update($ctx, $chunk);
        }
        return hash_final($ctx, true);
    }

    public function verifySignature(array $bytes, string $signature)
    {
        $ctx = hash_init('sha256', HASH_HMAC, $this->keyProvider->getKey($this->hmacKeyId));
        foreach ($bytes as $chunk) {
            hash_update($ctx, $chunk);
        }
        $actual = hash_final($ctx, true);
        return $actual == $signature;
    }
};
