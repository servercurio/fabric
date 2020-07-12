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

import com.servercurio.fabric.security.Hash;
import com.servercurio.fabric.security.MacAlgorithm;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.Key;
import java.util.concurrent.Future;

public interface MacProvider {

    /**
     * @return
     */
    default MacAlgorithm getDefaultMacAlgorithm() {
        return MacAlgorithm.HMAC_SHA_384;
    }

    /**
     * @param key
     * @param stream
     * @return
     */
    default Future<Hash> authenticateAsync(final Key key, final InputStream stream) {
        return authenticateAsync(key, stream, getDefaultMacAlgorithm());
    }

    /**
     * @param key
     * @param stream
     * @param algorithm
     * @return
     */
    Future<Hash> authenticateAsync(final Key key, final InputStream stream, final MacAlgorithm algorithm);

    /**
     * @param key
     * @param data
     * @return
     */
    default Future<Hash> authenticateAsync(final Key key, final byte[] data) {
        return authenticateAsync(key, data, getDefaultMacAlgorithm());
    }

    /**
     * @param key
     * @param data
     * @param algorithm
     * @return
     */
    Future<Hash> authenticateAsync(final Key key, final byte[] data, final MacAlgorithm algorithm);

    /**
     * @param key
     * @param leftHash
     * @param rightHash
     * @return
     */
    default Future<Hash> authenticateAsync(final Key key, final Hash leftHash, final Hash rightHash) {
        return authenticateAsync(key, leftHash, rightHash, getDefaultMacAlgorithm());
    }

    /**
     * @param key
     * @param leftHash
     * @param rightHash
     * @param algorithm
     * @return
     */
    Future<Hash> authenticateAsync(final Key key, final Hash leftHash, final Hash rightHash,
                                   final MacAlgorithm algorithm);

    /**
     * @param key
     * @param buffer
     * @return
     */
    default Future<Hash> authenticateAsync(final Key key, final ByteBuffer buffer) {
        return authenticateAsync(key, buffer, getDefaultMacAlgorithm());
    }

    /**
     * @param key
     * @param buffer
     * @param algorithm
     * @return
     */
    Future<Hash> authenticateAsync(final Key key, final ByteBuffer buffer, final MacAlgorithm algorithm);

    /**
     * @param key
     * @param stream
     * @return
     */
    default Hash authenticateSync(final Key key, final InputStream stream) {
        return authenticateSync(key, stream, getDefaultMacAlgorithm());
    }

    /**
     * @param key
     * @param stream
     * @param algorithm
     * @return
     */
    Hash authenticateSync(final Key key, final InputStream stream, final MacAlgorithm algorithm);

    /**
     * @param key
     * @param data
     * @return
     */
    default Hash authenticateSync(final Key key, final byte[] data) {
        return authenticateSync(key, data, getDefaultMacAlgorithm());
    }

    /**
     * @param key
     * @param data
     * @param algorithm
     * @return
     */
    Hash authenticateSync(final Key key, final byte[] data, final MacAlgorithm algorithm);

    /**
     * @param key
     * @param leftHash
     * @param rightHash
     * @return
     */
    default Hash authenticateSync(final Key key, final Hash leftHash, final Hash rightHash) {
        return authenticateSync(key, leftHash, rightHash, getDefaultMacAlgorithm());
    }

    /**
     * @param key
     * @param leftHash
     * @param rightHash
     * @param algorithm
     * @return
     */
    Hash authenticateSync(final Key key, final Hash leftHash, final Hash rightHash,
                                  final MacAlgorithm algorithm);

    /**
     * @param key
     * @param buffer
     * @return
     */
    default Hash authenticateSync(final Key key, final ByteBuffer buffer) {
        return authenticateSync(key, buffer, getDefaultMacAlgorithm());
    }

    /**
     * @param key
     * @param buffer
     * @param algorithm
     * @return
     */
    Hash authenticateSync(final Key key, final ByteBuffer buffer, final MacAlgorithm algorithm);
}
