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
import java.util.concurrent.Future;

public interface DigestProvider {

    /**
     * @return
     */
    default HashAlgorithm getDefaultAlgorithm() {
        return HashAlgorithm.SHA_384;
    }

    /**
     * @param stream
     * @return
     */
    default Future<Hash> digestAsync(final InputStream stream) {
        return digestAsync(getDefaultAlgorithm(), stream);
    }

    /**
     * @param algorithm
     * @param stream
     * @return
     */
    Future<Hash> digestAsync(final HashAlgorithm algorithm, final InputStream stream);

    /**
     * @param data
     * @return
     */
    default Future<Hash> digestAsync(final byte[] data) {
        return digestAsync(getDefaultAlgorithm(), data);
    }

    /**
     * @param algorithm
     * @param data
     * @return
     */
    Future<Hash> digestAsync(final HashAlgorithm algorithm, final byte[] data);

    /**
     * @param hashes
     * @return
     */
    default Future<Hash> digestAsync(final Hash... hashes) {
        return digestAsync(getDefaultAlgorithm(), hashes);
    }

    /**
     * @param algorithm
     * @param hashes
     * @return
     */
    Future<Hash> digestAsync(final HashAlgorithm algorithm, final Hash... hashes);

    /**
     * @param buffer
     * @return
     */
    default Future<Hash> digestAsync(final ByteBuffer buffer) {
        return digestAsync(getDefaultAlgorithm(), buffer);
    }

    /**
     * @param algorithm
     * @param buffer
     * @return
     */
    Future<Hash> digestAsync(final HashAlgorithm algorithm, final ByteBuffer buffer);

    /**
     * @param stream
     * @return
     */
    default Hash digestSync(final InputStream stream) {
        return digestSync(getDefaultAlgorithm(), stream);
    }

    /**
     * @param algorithm
     * @param stream
     * @return
     */
    Hash digestSync(final HashAlgorithm algorithm, final InputStream stream);

    /**
     * @param data
     * @return
     */
    default Hash digestSync(final byte[] data) {
        return digestSync(getDefaultAlgorithm(), data);
    }

    /**
     * @param algorithm
     * @param data
     * @return
     */
    Hash digestSync(final HashAlgorithm algorithm, final byte[] data);

    /**
     * @param hashes
     * @return
     */
    default Hash digestSync(final Hash... hashes) {
        return digestSync(getDefaultAlgorithm(), hashes);
    }

    /**
     * @param algorithm
     * @param hashes
     * @return
     */
    Hash digestSync(final HashAlgorithm algorithm, final Hash... hashes);

    /**
     * @param buffer
     * @return
     */
    default Hash digestSync(final ByteBuffer buffer) {
        return digestSync(getDefaultAlgorithm(), buffer);
    }

    /**
     * @param algorithm
     * @param buffer
     * @return
     */
    Hash digestSync(final HashAlgorithm algorithm, final ByteBuffer buffer);
}
