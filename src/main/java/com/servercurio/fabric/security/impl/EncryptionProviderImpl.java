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
import com.servercurio.fabric.security.CryptographyException;
import com.servercurio.fabric.security.spi.EncryptionProvider;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.concurrent.Future;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class EncryptionProviderImpl implements EncryptionProvider {

    private static final int GCM_NONCE_SIZE = 12;
    private static final int GCM_TAG_SIZE = 128;

    private static final int CTR_COUNTER_SIZE = 4;


    private final DefaultCryptographyImpl crypto;

    public EncryptionProviderImpl(final DefaultCryptographyImpl crypto) {
        this.crypto = crypto;
    }

    private byte[] deriveCounterIv(final int blockSize, final int counterLen, final byte[] iv) {
        final int supportedIvLength = blockSize - counterLen;
        final byte[] counterIv = new byte[blockSize];

        System.arraycopy(iv, 0, counterIv, 0, Math.min(supportedIvLength, iv.length));
        return counterIv;
    }

    private int deriveNonceSize(final CipherTransformation algorithm) {
        final Cipher cipher = crypto.primitive(algorithm);

        return switch (algorithm.getMode()) {
            case GCM -> GCM_NONCE_SIZE;
            case CTR -> cipher.getBlockSize() - CTR_COUNTER_SIZE;
            default -> cipher.getBlockSize();
        };
    }

    private AlgorithmParameterSpec deriveParameters(final CipherTransformation algorithm, final byte[] iv) {
        final Cipher cipher = crypto.primitive(algorithm);

        return switch (algorithm.getMode()) {
            case GCM -> new GCMParameterSpec(GCM_TAG_SIZE, iv);
            case CTR -> new IvParameterSpec(deriveCounterIv(cipher.getBlockSize(), CTR_COUNTER_SIZE, iv));
            default -> new IvParameterSpec(iv);
        };
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
        final Cipher cipher = crypto.primitive(algorithm);

        try {
            final AlgorithmParameterSpec parameterSpec = deriveParameters(algorithm, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

            try (final CipherInputStream iStream = new CipherInputStream(cipherStream, cipher)) {
                iStream.transferTo(clearStream);
                clearStream.flush();
            }

        } catch (IOException | GeneralSecurityException ex) {
            throw new CryptographyException(ex);
        }
    }

    @Override
    public byte[] decryptSync(final CipherTransformation algorithm, final SecretKey key, final byte[] iv,
                              final byte[] data) {
        final Cipher cipher = crypto.primitive(algorithm);

        try {
            final AlgorithmParameterSpec parameterSpec = deriveParameters(algorithm, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

            return cipher.doFinal(data);
        } catch (GeneralSecurityException ex) {
            throw new CryptographyException(ex);
        }
    }

    @Override
    public ByteBuffer decryptSync(final CipherTransformation algorithm, final SecretKey key, final byte[] iv,
                                  final ByteBuffer buffer) {
        final Cipher cipher = crypto.primitive(algorithm);

        try {
            final AlgorithmParameterSpec parameterSpec = deriveParameters(algorithm, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

            final ByteBuffer clearText = ByteBuffer.allocate(cipher.getOutputSize(buffer.capacity()));
            cipher.doFinal(buffer, clearText);

            return clearText;
        } catch (GeneralSecurityException ex) {
            throw new CryptographyException(ex);
        }
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
        final Cipher cipher = crypto.primitive(algorithm);

        try {
            final AlgorithmParameterSpec parameterSpec = deriveParameters(algorithm, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

            try (final CipherOutputStream oStream = new CipherOutputStream(cipherStream, cipher)) {
                clearStream.transferTo(oStream);
                oStream.flush();
                cipherStream.flush();
            }

        } catch (IOException | GeneralSecurityException ex) {
            throw new CryptographyException(ex);
        }
    }

    @Override
    public byte[] encryptSync(final CipherTransformation algorithm, final SecretKey key, final byte[] iv,
                              final byte[] data) {
        final Cipher cipher = crypto.primitive(algorithm);

        try {
            final AlgorithmParameterSpec parameterSpec = deriveParameters(algorithm, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

            return cipher.doFinal(data);
        } catch (GeneralSecurityException ex) {
            throw new CryptographyException(ex);
        }
    }

    @Override
    public ByteBuffer encryptSync(final CipherTransformation algorithm, final SecretKey key, final byte[] iv,
                                  final ByteBuffer buffer) {
        final Cipher cipher = crypto.primitive(algorithm);

        try {
            final AlgorithmParameterSpec parameterSpec = deriveParameters(algorithm, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

            final ByteBuffer cipherText = ByteBuffer.allocate(cipher.getOutputSize(buffer.capacity()));
            cipher.doFinal(buffer, cipherText);

            return cipherText;
        } catch (GeneralSecurityException ex) {
            throw new CryptographyException(ex);
        }
    }

    @Override
    public Future<byte[]> nonceAsync(final CipherTransformation algorithm) {
        return crypto.executorService().submit(() -> nonceSync(algorithm));
    }

    @Override
    public byte[] nonceSync(final CipherTransformation algorithm) {
        final int nonceSize = deriveNonceSize(algorithm);
        final byte[] nonce = new byte[nonceSize];
        final SecureRandom random = crypto.random();

        random.nextBytes(nonce);
        return nonce;
    }
}
