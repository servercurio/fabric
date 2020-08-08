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

import com.servercurio.fabric.security.CipherAlgorithm;
import com.servercurio.fabric.security.CipherMode;
import com.servercurio.fabric.security.CipherPadding;
import com.servercurio.fabric.security.CipherTransformation;
import com.servercurio.fabric.security.Cryptography;
import com.servercurio.fabric.security.CryptographyException;
import com.servercurio.fabric.security.spi.EncryptionProvider;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.concurrent.Future;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Positive;

/**
 * Default {@code Fabric Unified Cryptography API} provider implementation that encapsulates all of the available
 * symmetric and asymmetric encryption functionality. The default algorithm is {@link CipherAlgorithm#AES} using {@link
 * CipherMode#GCM} mode and {@link CipherPadding#NONE} padding which is the minimum recommended algorithm that is C-NSA
 * compliant.
 *
 * @author Nathan Klick
 * @see Cryptography
 * @see CipherTransformation
 * @see CipherAlgorithm
 * @see CipherMode
 * @see CipherPadding
 */
public class EncryptionProviderImpl implements EncryptionProvider {

    private static final int GCM_NONCE_SIZE = 12;

    private static final int GCM_TAG_SIZE = 128;

    private static final int CTR_COUNTER_SIZE = 4;


    @NotNull
    private final DefaultCryptographyImpl crypto;

    public EncryptionProviderImpl(@NotNull final DefaultCryptographyImpl crypto) {
        this.crypto = crypto;
    }

    private static byte[] deriveCounterIv(@Positive final int blockSize, @Positive final int counterLen,
                                          @NotEmpty final byte[] iv) {
        final int supportedIvLength = blockSize - counterLen;
        final byte[] counterIv = new byte[blockSize];

        System.arraycopy(iv, 0, counterIv, 0, Math.min(supportedIvLength, iv.length));
        return counterIv;
    }

    private int deriveNonceSize(@NotNull final CipherTransformation algorithm) {
        final Cipher cipher = crypto.primitive(algorithm);

        switch (algorithm.getMode()) {
            case GCM:
                return GCM_NONCE_SIZE;
            case CTR:
                return cipher.getBlockSize() - CTR_COUNTER_SIZE;
            default:
                return cipher.getBlockSize();
        }
    }

    private AlgorithmParameterSpec deriveParameters(@NotNull final CipherTransformation algorithm,
                                                    @NotEmpty final byte[] iv) {
        final Cipher cipher = crypto.primitive(algorithm);

        switch (algorithm.getMode()) {
            case GCM:
                return new GCMParameterSpec(GCM_TAG_SIZE, iv);
            case CTR:
                return new IvParameterSpec(deriveCounterIv(cipher.getBlockSize(), CTR_COUNTER_SIZE, iv));
            default:
                return new IvParameterSpec(iv);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<?> decryptAsync(@NotNull final CipherTransformation algorithm, @NotNull final Key key,
                                  @NotEmpty final byte[] iv, @NotNull final InputStream cipherStream,
                                  @NotNull final OutputStream clearStream) {
        return crypto.executorService().submit(() -> decryptSync(algorithm, key, iv, cipherStream, clearStream));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<byte[]> decryptAsync(@NotNull final CipherTransformation algorithm, @NotNull final Key key,
                                       @NotEmpty final byte[] iv, @NotEmpty final byte[] data) {
        return crypto.executorService().submit(() -> decryptSync(algorithm, key, iv, data));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<ByteBuffer> decryptAsync(@NotNull final CipherTransformation algorithm, @NotNull final Key key,
                                           @NotEmpty final byte[] iv, @NotNull final ByteBuffer buffer) {
        return crypto.executorService().submit(() -> decryptSync(algorithm, key, iv, buffer));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void decryptSync(@NotNull final CipherTransformation algorithm, @NotNull final Key key,
                            @NotEmpty final byte[] iv, @NotNull final InputStream cipherStream,
                            @NotNull final OutputStream clearStream) {
        final Cipher cipher = crypto.primitive(algorithm);

        try {
            final AlgorithmParameterSpec parameterSpec = deriveParameters(algorithm, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

            final CipherInputStream iStream = new CipherInputStream(cipherStream, cipher);
            iStream.transferTo(clearStream);
            clearStream.flush();

            if (clearStream instanceof FileOutputStream) {
                final FileOutputStream fos = (FileOutputStream) clearStream;
                fos.getChannel().force(true);
                fos.getFD().sync();
            }
        } catch (IOException | GeneralSecurityException ex) {
            throw new CryptographyException(ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] decryptSync(@NotNull final CipherTransformation algorithm, @NotNull final Key key,
                              @NotEmpty final byte[] iv, @NotEmpty final byte[] data) {
        final Cipher cipher = crypto.primitive(algorithm);

        try {
            final AlgorithmParameterSpec parameterSpec = deriveParameters(algorithm, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

            return cipher.doFinal(data);
        } catch (GeneralSecurityException ex) {
            throw new CryptographyException(ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ByteBuffer decryptSync(@NotNull final CipherTransformation algorithm, @NotNull final Key key,
                                  @NotEmpty final byte[] iv, @NotNull final ByteBuffer buffer) {
        final Cipher cipher = crypto.primitive(algorithm);

        try {
            final AlgorithmParameterSpec parameterSpec = deriveParameters(algorithm, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

            final ByteBuffer clearText = ByteBuffer.allocate(cipher.getOutputSize(buffer.capacity()));
            cipher.doFinal(buffer, clearText);

            return clearText.flip();
        } catch (GeneralSecurityException ex) {
            throw new CryptographyException(ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<?> encryptAsync(@NotNull final CipherTransformation algorithm, @NotNull final Key key,
                                  @NotEmpty final byte[] iv, @NotNull final InputStream clearStream,
                                  @NotNull final OutputStream cipherStream) {
        return crypto.executorService().submit(() -> encryptSync(algorithm, key, iv, clearStream, cipherStream));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<byte[]> encryptAsync(@NotNull final CipherTransformation algorithm, @NotNull final Key key,
                                       @NotEmpty final byte[] iv, @NotEmpty final byte[] data) {
        return crypto.executorService().submit(() -> encryptSync(algorithm, key, iv, data));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<ByteBuffer> encryptAsync(@NotNull final CipherTransformation algorithm, @NotNull final Key key,
                                           @NotEmpty final byte[] iv, @NotNull final ByteBuffer buffer) {
        return crypto.executorService().submit(() -> encryptSync(algorithm, key, iv, buffer));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void encryptSync(@NotNull final CipherTransformation algorithm, @NotNull final Key key,
                            @NotEmpty final byte[] iv, @NotNull final InputStream clearStream,
                            @NotNull final OutputStream cipherStream) {
        final Cipher cipher = crypto.primitive(algorithm);

        try {
            final AlgorithmParameterSpec parameterSpec = deriveParameters(algorithm, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

            try (final CipherOutputStream oStream = new CipherOutputStream(cipherStream, cipher)) {

                clearStream.transferTo(oStream);
                oStream.flush();
                cipherStream.flush();

                if (cipherStream instanceof FileOutputStream) {
                    final FileOutputStream fos = (FileOutputStream) cipherStream;
                    fos.getChannel().force(true);
                    fos.getFD().sync();
                }
            }
        } catch (IOException | GeneralSecurityException ex) {
            throw new CryptographyException(ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] encryptSync(@NotNull final CipherTransformation algorithm, @NotNull final Key key,
                              @NotEmpty final byte[] iv, @NotEmpty final byte[] data) {
        final Cipher cipher = crypto.primitive(algorithm);

        try {
            final AlgorithmParameterSpec parameterSpec = deriveParameters(algorithm, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

            return cipher.doFinal(data);
        } catch (GeneralSecurityException ex) {
            throw new CryptographyException(ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ByteBuffer encryptSync(@NotNull final CipherTransformation algorithm, @NotNull final Key key,
                                  @NotEmpty final byte[] iv, @NotNull final ByteBuffer buffer) {
        final Cipher cipher = crypto.primitive(algorithm);

        try {
            final AlgorithmParameterSpec parameterSpec = deriveParameters(algorithm, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

            final ByteBuffer cipherText = ByteBuffer.allocate(cipher.getOutputSize(buffer.capacity()));
            cipher.doFinal(buffer, cipherText);

            return cipherText.flip();
        } catch (GeneralSecurityException ex) {
            throw new CryptographyException(ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<byte[]> nonceAsync(@NotNull final CipherTransformation algorithm) {
        return crypto.executorService().submit(() -> nonceSync(algorithm));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] nonceSync(@NotNull final CipherTransformation algorithm) {
        final int nonceSize = deriveNonceSize(algorithm);
        final byte[] nonce = new byte[nonceSize];
        final SecureRandom random = crypto.random();

        random.nextBytes(nonce);
        return nonce;
    }
}
