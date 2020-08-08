/*
 * Copyright 2019-2020 Server Curio
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.servercurio.fabric.security.spi;

import com.servercurio.fabric.security.Cryptography;
import com.servercurio.fabric.security.Hash;
import com.servercurio.fabric.security.MacAlgorithm;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.Key;
import java.util.concurrent.Future;

/**
 * {@code Fabric Unified Cryptography API} provider definition that encapsulates all of the available message digest
 * functionality. The default algorithm is {@link MacAlgorithm#HMAC_SHA_384} which is the minimum recommended algorithm
 * that is C-NSA compliant. Provider implementations may choose to override the default; however, it is recommended that
 * the default algorithm be a C-NSA compliant algorithm.
 *
 * @author Nathan Klick
 * @see Cryptography
 * @see MacAlgorithm
 */
public interface MacProvider {

    /**
     * Returns the default algorithm. This is the algorithm that will be used when calling the overloaded methods that
     * do not accept the algorithm as a parameter.
     *
     * @return the default algorithm, not null
     */
    default MacAlgorithm getDefaultAlgorithm() {
        return MacAlgorithm.HMAC_SHA_384;
    }

    /**
     * @param key
     * @param stream
     * @return
     */
    default Future<Hash> authenticateAsync(final Key key, final InputStream stream) {
        return authenticateAsync(getDefaultAlgorithm(), key, stream);
    }

    /**
     * @param algorithm
     * @param key
     * @param stream
     * @return
     */
    Future<Hash> authenticateAsync(final MacAlgorithm algorithm, final Key key, final InputStream stream);

    /**
     * @param key
     * @param data
     * @return
     */
    default Future<Hash> authenticateAsync(final Key key, final byte[] data) {
        return authenticateAsync(getDefaultAlgorithm(), key, data);
    }

    /**
     * @param algorithm
     * @param key
     * @param data
     * @return
     */
    Future<Hash> authenticateAsync(final MacAlgorithm algorithm, final Key key, final byte[] data);

    /**
     * @param key
     * @param hashes
     * @return
     */
    default Future<Hash> authenticateAsync(final Key key, final Hash... hashes) {
        return authenticateAsync(getDefaultAlgorithm(), key, hashes);
    }

    /**
     * @param algorithm
     * @param key
     * @param hashes
     * @return
     */
    Future<Hash> authenticateAsync(final MacAlgorithm algorithm, final Key key, final Hash... hashes);

    /**
     * @param key
     * @param buffer
     * @return
     */
    default Future<Hash> authenticateAsync(final Key key, final ByteBuffer buffer) {
        return authenticateAsync(getDefaultAlgorithm(), key, buffer);
    }

    /**
     * @param algorithm
     * @param key
     * @param buffer
     * @return
     */
    Future<Hash> authenticateAsync(final MacAlgorithm algorithm, final Key key, final ByteBuffer buffer);

    /**
     * @param key
     * @param stream
     * @return
     */
    default Hash authenticateSync(final Key key, final InputStream stream) {
        return authenticateSync(getDefaultAlgorithm(), key, stream);
    }

    /**
     * @param algorithm
     * @param key
     * @param stream
     * @return
     */
    Hash authenticateSync(final MacAlgorithm algorithm, final Key key, final InputStream stream);

    /**
     * @param key
     * @param data
     * @return
     */
    default Hash authenticateSync(final Key key, final byte[] data) {
        return authenticateSync(getDefaultAlgorithm(), key, data);
    }

    /**
     * @param algorithm
     * @param key
     * @param data
     * @return
     */
    Hash authenticateSync(final MacAlgorithm algorithm, final Key key, final byte[] data);

    /**
     * @param key
     * @param hashes
     * @return
     */
    default Hash authenticateSync(final Key key, final Hash... hashes) {
        return authenticateSync(getDefaultAlgorithm(), key, hashes);
    }

    /**
     * @param algorithm
     * @param key
     * @param hashes
     * @return
     */
    Hash authenticateSync(final MacAlgorithm algorithm, final Key key, final Hash... hashes);

    /**
     * @param key
     * @param buffer
     * @return
     */
    default Hash authenticateSync(final Key key, final ByteBuffer buffer) {
        return authenticateSync(getDefaultAlgorithm(), key, buffer);
    }

    /**
     * @param algorithm
     * @param key
     * @param buffer
     * @return
     */
    Hash authenticateSync(final MacAlgorithm algorithm, final Key key, final ByteBuffer buffer);
}
