<?php
/*
 * Copyright (c) 2018 Couchbase, Inc.
 *
 * Use of this software is subject to the Couchbase Inc. Enterprise Subscription License Agreement
 * which may be found at https://www.couchbase.com/ESLA-11132015.
 */

namespace Couchbase;

/**
 * Interface for fetching keys from the key stores
 */
interface KeyProvider
{
    /**
     * Load key by name
     *
     * @param  string $id   Name or identifier of the key
     * @return string contents of the key
     */
    public function getKey(string $id);
}
