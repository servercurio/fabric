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

import com.servercurio.fabric.security.CipherTransformation;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.concurrent.Future;
import javax.crypto.SecretKey;

public interface EncryptionProvider {

    /**
     * @return
     */
    default CipherTransformation getDefaultAlgorithm() {
        return new CipherTransformation();
    }

    default Future<?> decryptAsync(final SecretKey key, final byte[] iv, final InputStream cipherStream,
                                      final OutputStream clearStream) {
        return decryptAsync(getDefaultAlgorithm(), key, iv, cipherStream, clearStream);
    }

    Future<?> decryptAsync(final CipherTransformation algorithm, final SecretKey key, final byte[] iv,
                              final InputStream cipherStream, final OutputStream clearStream);

    default Future<byte[]> decryptAsync(final SecretKey key, final byte[] iv, final byte[] data) {
        return decryptAsync(getDefaultAlgorithm(), key, iv, data);
    }

    Future<byte[]> decryptAsync(final CipherTransformation algorithm,
                                final SecretKey key,
                                final byte[] iv,
                                final byte[] data);

    default Future<ByteBuffer> decryptAsync(final SecretKey key, final byte[] iv, final ByteBuffer buffer) {
        return decryptAsync(getDefaultAlgorithm(), key, iv, buffer);
    }

    Future<ByteBuffer> decryptAsync(final CipherTransformation algorithm,
                                    final SecretKey key,
                                    final byte[] iv,
                                    final ByteBuffer buffer);

    ////

    default void decryptSync(final SecretKey key, final byte[] iv, final InputStream cipherStream,
                             final OutputStream clearStream) {
        decryptSync(getDefaultAlgorithm(), key, iv, cipherStream, clearStream);
    }

    void decryptSync(final CipherTransformation algorithm,
                     final SecretKey key,
                     final byte[] iv,
                     final InputStream cipherStream,
                     final OutputStream clearStream);

    default byte[] decryptSync(final SecretKey key, final byte[] iv, final byte[] data) {
        return decryptSync(getDefaultAlgorithm(), key, iv, data);
    }

    byte[] decryptSync(final CipherTransformation algorithm, final SecretKey key, final byte[] iv, final byte[] data);

    default ByteBuffer decryptSync(final SecretKey key, final byte[] iv, final ByteBuffer buffer) {
        return decryptSync(getDefaultAlgorithm(), key, iv, buffer);
    }

    ByteBuffer decryptSync(final CipherTransformation algorithm,
                           final SecretKey key,
                           final byte[] iv,
                           final ByteBuffer buffer);

    //////

    default Future<?> encryptAsync(final SecretKey key, final byte[] iv, final InputStream clearStream,
                                      final OutputStream cipherStream) {
        return encryptAsync(getDefaultAlgorithm(), key, iv, clearStream, cipherStream);
    }

    Future<?> encryptAsync(final CipherTransformation algorithm, final SecretKey key, final byte[] iv,
                              final InputStream clearStream, final OutputStream cipherStream);

    default Future<byte[]> encryptAsync(final SecretKey key, final byte[] iv, final byte[] data) {
        return encryptAsync(getDefaultAlgorithm(), key, iv, data);
    }

    Future<byte[]> encryptAsync(final CipherTransformation algorithm, final SecretKey key, final byte[] iv,
                                final byte[] data);

    default Future<ByteBuffer> encryptAsync(final SecretKey key, final byte[] iv, final ByteBuffer buffer) {
        return encryptAsync(getDefaultAlgorithm(), key, iv, buffer);
    }

    Future<ByteBuffer> encryptAsync(final CipherTransformation algorithm, final SecretKey key, final byte[] iv,
                                    final ByteBuffer buffer);

    default void encryptSync(final SecretKey key, final byte[] iv, final InputStream clearStream,
                             final OutputStream cipherStream) {
        encryptSync(getDefaultAlgorithm(), key, iv, clearStream, cipherStream);
    }

    void encryptSync(final CipherTransformation algorithm, final SecretKey key, final byte[] iv,
                     final InputStream clearStream, final OutputStream cipherStream);

    default byte[] encryptSync(final SecretKey key, final byte[] iv, final byte[] data) {
        return encryptSync(getDefaultAlgorithm(), key, iv, data);
    }

    byte[] encryptSync(final CipherTransformation algorithm, final SecretKey key, final byte[] iv, final byte[] data);

    default ByteBuffer encryptSync(final SecretKey key, final byte[] iv, final ByteBuffer buffer) {
        return encryptSync(getDefaultAlgorithm(), key, iv, buffer);
    }

    ByteBuffer encryptSync(final CipherTransformation algorithm, final SecretKey key, final byte[] iv,
                           final ByteBuffer buffer);
}
