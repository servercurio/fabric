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

package com.servercurio.fabric.security.impl;

import com.servercurio.fabric.security.CipherTransformation;
import com.servercurio.fabric.security.spi.EncryptionProvider;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.concurrent.Future;
import javax.crypto.SecretKey;

public class EncryptionProviderImpl implements EncryptionProvider {

    private final DefaultCryptographyImpl crypto;

    public EncryptionProviderImpl(final DefaultCryptographyImpl crypto) {
        this.crypto = crypto;
    }

    @Override
    public Future<?> decryptAsync(final CipherTransformation algorithm, final SecretKey key, final byte[] iv,
                                     final InputStream cipherStream, final OutputStream clearStream) {
        return crypto.executorService().submit(() -> decryptSync(algorithm, key, iv, cipherStream, clearStream));
    }

    @Override
    public Future<byte[]> decryptAsync(final CipherTransformation algorithm, final SecretKey key, final byte[] iv,
                                       final byte[] data) {
        return crypto.executorService().submit(() -> decryptSync(algorithm, key, iv, data));
    }

    @Override
    public Future<ByteBuffer> decryptAsync(final CipherTransformation algorithm, final SecretKey key, final byte[] iv,
                                           final ByteBuffer buffer) {
        return crypto.executorService().submit(() -> decryptSync(algorithm, key, iv, buffer));
    }

    @Override
    public void decryptSync(final CipherTransformation algorithm, final SecretKey key, final byte[] iv,
                            final InputStream cipherStream, final OutputStream clearStream) {

    }

    @Override
    public byte[] decryptSync(final CipherTransformation algorithm, final SecretKey key, final byte[] iv,
                              final byte[] data) {
        return new byte[0];
    }

    @Override
    public ByteBuffer decryptSync(final CipherTransformation algorithm, final SecretKey key, final byte[] iv,
                                  final ByteBuffer buffer) {
        return null;
    }

    @Override
    public Future<?> encryptAsync(final CipherTransformation algorithm, final SecretKey key, final byte[] iv,
                                     final InputStream clearStream, final OutputStream cipherStream) {
        return crypto.executorService().submit(() -> encryptSync(algorithm, key, iv, clearStream, cipherStream));
    }

    @Override
    public Future<byte[]> encryptAsync(final CipherTransformation algorithm, final SecretKey key, final byte[] iv,
                                       final byte[] data) {
        return crypto.executorService().submit(() -> encryptSync(algorithm, key, iv, data));
    }

    @Override
    public Future<ByteBuffer> encryptAsync(final CipherTransformation algorithm, final SecretKey key, final byte[] iv,
                                           final ByteBuffer buffer) {
        return crypto.executorService().submit(() -> encryptSync(algorithm, key, iv, buffer));
    }

    @Override
    public void encryptSync(final CipherTransformation algorithm, final SecretKey key, final byte[] iv,
                            final InputStream clearStream, final OutputStream cipherStream) {

    }

    @Override
    public byte[] encryptSync(final CipherTransformation algorithm, final SecretKey key, final byte[] iv,
                              final byte[] data) {
        return new byte[0];
    }

    @Override
    public ByteBuffer encryptSync(final CipherTransformation algorithm, final SecretKey key, final byte[] iv,
                                  final ByteBuffer buffer) {
        return null;
    }
}
