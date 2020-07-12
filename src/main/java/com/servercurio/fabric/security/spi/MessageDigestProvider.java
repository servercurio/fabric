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
import com.servercurio.fabric.security.HashAlgorithm;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.Future;

public interface MessageDigestProvider {

    /**
     * @return
     */
    default HashAlgorithm getDefaultHashAlgorithm() {
        return HashAlgorithm.SHA_384;
    }

    /**
     * @param stream
     * @return
     */
    default Future<Hash> digestAsync(final InputStream stream) {
        return digestAsync(stream, getDefaultHashAlgorithm());
    }

    /**
     * @param stream
     * @param algorithm
     * @return
     */
    Future<Hash> digestAsync(final InputStream stream, final HashAlgorithm algorithm);

    /**
     * @param data
     * @return
     */
    default Future<Hash> digestAsync(final byte[] data) {
        return digestAsync(data, getDefaultHashAlgorithm());
    }

    /**
     * @param data
     * @param algorithm
     * @return
     */
    Future<Hash> digestAsync(final byte[] data, final HashAlgorithm algorithm);

    /**
     * @param leftHash
     * @param rightHash
     * @return
     */
    default Future<Hash> digestAsync(final Hash leftHash, final Hash rightHash) {
        return digestAsync(leftHash, rightHash, getDefaultHashAlgorithm());
    }

    /**
     * @param leftHash
     * @param rightHash
     * @param algorithm
     * @return
     */
    Future<Hash> digestAsync(final Hash leftHash, final Hash rightHash, final HashAlgorithm algorithm);

    /**
     * @param buffer
     * @return
     */
    default Future<Hash> digestAsync(final ByteBuffer buffer) {
        return digestAsync(buffer, getDefaultHashAlgorithm());
    }

    /**
     * @param buffer
     * @param algorithm
     * @return
     */
    Future<Hash> digestAsync(final ByteBuffer buffer, final HashAlgorithm algorithm);

    /**
     * @param stream
     * @return
     */
    default Hash digestSync(final InputStream stream) {
        return digestSync(stream, getDefaultHashAlgorithm());
    }

    /**
     * @param stream
     * @param algorithm
     * @return
     */
    Hash digestSync(final InputStream stream, final HashAlgorithm algorithm);

    /**
     * @param data
     * @return
     */
    default Hash digestSync(final byte[] data) {
        return digestSync(data, getDefaultHashAlgorithm());
    }

    /**
     * @param data
     * @param algorithm
     * @return
     */
    Hash digestSync(final byte[] data, final HashAlgorithm algorithm);

    /**
     * @param leftHash
     * @param rightHash
     * @return
     */
    default Hash digestSync(final Hash leftHash, final Hash rightHash) {
        return digestSync(leftHash, rightHash, getDefaultHashAlgorithm());
    }

    /**
     * @param leftHash
     * @param rightHash
     * @param algorithm
     * @return
     */
    Hash digestSync(final Hash leftHash, final Hash rightHash, final HashAlgorithm algorithm);

    /**
     * @param buffer
     * @return
     */
    default Hash digestSync(final ByteBuffer buffer) {
        return digestSync(buffer, getDefaultHashAlgorithm());
    }

    /**
     * @param buffer
     * @param algorithm
     * @return
     */
    Hash digestSync(final ByteBuffer buffer, final HashAlgorithm algorithm);
}
