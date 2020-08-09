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

import com.servercurio.fabric.lang.Validators;
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

import static com.servercurio.fabric.lang.Validators.throwIfArgumentIsEmpty;
import static com.servercurio.fabric.lang.Validators.throwIfArgIsNotPositive;
import static com.servercurio.fabric.lang.Validators.throwIfArgIsNull;

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

    /**
     * The {@code crypto} field name represented as a string value.
     */
    private static final String CRYPTO_FIELD = "crypto";

    /**
     * The {@code blockSize} parameter name represented as a string value.
     */
    private static final String BLOCK_SIZE_PARAM = "blockSize";

    /**
     * The {@code counterLength} parameter name represented as a string value.
     */
    private static final String COUNTER_LENGTH_PARAM = "counterLength";

    /**
     * The {@code iv} parameter name represented as a string value.
     */
    private static final String IV_PARAM = "iv";

    /**
     * The {@code algorithm} parameter name represented as a string value.
     */
    private static final String ALGORITHM_PARAM = "algorithm";

    /**
     * The {@code key} parameter name represented as a string value.
     */
    private static final String KEY_PARAM = "key";

    /**
     * The {@code cipherStream} parameter name represented as a string value.
     */
    private static final String CIPHER_STREAM_PARAM = "cipherStream";

    /**
     * The {@code clearStream} parameter name represented as a string value.
     */
    private static final String CLEAR_STREAM_PARAM = "clearStream";

    /**
     * The {@code data} parameter name represented as a string value.
     */
    private static final String DATA_PARAM = "data";

    /**
     * The {@code buffer} parameter name represented as a string value.
     */
    private static final String BUFFER_PARAM = "buffer";

    /**
     * The preferred and largest nonce size in bytes supported by {@link CipherMode#GCM} that does not require an extra
     * block to be computed.
     */
    private static final int GCM_NONCE_SIZE = 12;

    /**
     * The preferred and largest tag size in bits supported by {@link CipherMode#GCM} that does not require an extra to
     * be computed.
     */
    private static final int GCM_TAG_SIZE = 128;

    /**
     * The preferred length in bytes of the counter portion of the IV when using {@link CipherMode#CTR}.
     */
    private static final int CTR_COUNTER_SIZE = 4;

    /**
     * The {@link Cryptography} implementation to which this provider is bound.
     */
    @NotNull
    private final DefaultCryptographyImpl crypto;

    /**
     * Constructs a new provider instance bound to the given {@link Cryptography} implementation.
     *
     * @param crypto
     *         the {@link DefaultCryptographyImpl} to which this provider is bound, not null
     */
    public EncryptionProviderImpl(@NotNull final DefaultCryptographyImpl crypto) {
        throwIfArgIsNull(crypto, CRYPTO_FIELD);

        this.crypto = crypto;
    }

    /**
     * Allocates an IV for {@link CipherMode#CTR} that ensures {@code counterLen} bytes are reserved and zero-filled for
     * the counter. If the supplied IV is longer than {@code blockSize - counterLen}, then it will be truncated to a
     * length of {@code blockSize - counterLen}.
     *
     * @param blockSize
     *         the blockSize in bytes of the cipher algorithm, postive integer
     * @param counterLength
     *         the desired length in bytes of the zero-filled counter, positive integer
     * @param iv
     *         the user-supplied nonce to be used for cipher initialization, not null
     * @return a byte array containing {@code blockSize - counterLen} bytes of the nonce with a trailing {@code
     *         counterLen} zero-filled bytes
     */
    private static byte[] deriveCounterIv(@Positive final int blockSize, @Positive final int counterLength,
                                          @NotEmpty final byte[] iv) {
        Validators.throwIfArgIsNotPositive(blockSize, BLOCK_SIZE_PARAM);
        Validators.throwIfArgIsNotPositive(counterLength, COUNTER_LENGTH_PARAM);
        throwIfArgumentIsEmpty(iv, IV_PARAM);

        final int supportedIvLength = blockSize - counterLength;
        final byte[] counterIv = new byte[blockSize];

        System.arraycopy(iv, 0, counterIv, 0, Math.min(supportedIvLength, iv.length));
        return counterIv;
    }

    /**
     * Computes the appropriate nonce size for the transformation given by the {@code algorithm} parameter.
     *
     * @param algorithm
     *         the chosen transformation, not null
     * @return a positive integer representing the number of bytes that should be used for the nonce
     */
    private int deriveNonceSize(@NotNull final CipherTransformation algorithm) {
        throwIfArgIsNull(algorithm, ALGORITHM_PARAM);

        final Cipher cipher = crypto.primitive(algorithm);

        //CHECKSTYLE.OFF: IndentationCheck
        switch (algorithm.getMode()) {
            case GCM:
                return GCM_NONCE_SIZE;
            case CTR:
                return cipher.getBlockSize() - CTR_COUNTER_SIZE;
            default:
                return cipher.getBlockSize();
        }
        //CHECKSTYLE.ON: IndentationCheck
    }

    /**
     * Creates the appropriate initialization parameters for the transformation given by the {@code algorithm} parameter
     * and the user supplied nonce given by the {@code iv} parameter.
     *
     * @param algorithm
     *         the chosen transformation, not null
     * @param iv
     *         the user-supplied nonce to be used for cipher initialization, not null
     * @return an appropriate {@link AlgorithmParameterSpec} instance that is properly configured, not null
     */
    private AlgorithmParameterSpec deriveParameters(@NotNull final CipherTransformation algorithm,
                                                    @NotEmpty final byte[] iv) {
        throwIfArgIsNull(algorithm, ALGORITHM_PARAM);
        throwIfArgumentIsEmpty(iv, IV_PARAM);

        final Cipher cipher = crypto.primitive(algorithm);

        //CHECKSTYLE.OFF: IndentationCheck
        switch (algorithm.getMode()) {
            case GCM:
                return new GCMParameterSpec(GCM_TAG_SIZE, iv);
            case CTR:
                return new IvParameterSpec(deriveCounterIv(cipher.getBlockSize(), CTR_COUNTER_SIZE, iv));
            default:
                return new IvParameterSpec(iv);
        }
        //CHECKSTYLE.ON: IndentationCheck
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
        throwIfArgIsNull(algorithm, ALGORITHM_PARAM);
        throwIfArgIsNull(key, KEY_PARAM);
        throwIfArgumentIsEmpty(iv, IV_PARAM);
        throwIfArgIsNull(cipherStream, CIPHER_STREAM_PARAM);
        throwIfArgIsNull(clearStream, CLEAR_STREAM_PARAM);

        final Cipher cipher = crypto.primitive(algorithm);

        try {
            final AlgorithmParameterSpec parameterSpec = deriveParameters(algorithm, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec, crypto.random());

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
        throwIfArgIsNull(algorithm, ALGORITHM_PARAM);
        throwIfArgIsNull(key, KEY_PARAM);
        throwIfArgumentIsEmpty(iv, IV_PARAM);
        throwIfArgumentIsEmpty(data, DATA_PARAM);

        final Cipher cipher = crypto.primitive(algorithm);

        try {
            final AlgorithmParameterSpec parameterSpec = deriveParameters(algorithm, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec, crypto.random());

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
        throwIfArgIsNull(algorithm, ALGORITHM_PARAM);
        throwIfArgIsNull(key, KEY_PARAM);
        throwIfArgumentIsEmpty(iv, IV_PARAM);
        throwIfArgIsNull(buffer, BUFFER_PARAM);

        final Cipher cipher = crypto.primitive(algorithm);

        try {
            final AlgorithmParameterSpec parameterSpec = deriveParameters(algorithm, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec, crypto.random());

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
        throwIfArgIsNull(algorithm, ALGORITHM_PARAM);
        throwIfArgIsNull(key, KEY_PARAM);
        throwIfArgumentIsEmpty(iv, IV_PARAM);
        throwIfArgIsNull(clearStream, CLEAR_STREAM_PARAM);
        throwIfArgIsNull(cipherStream, CIPHER_STREAM_PARAM);

        final Cipher cipher = crypto.primitive(algorithm);

        try {
            final AlgorithmParameterSpec parameterSpec = deriveParameters(algorithm, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec, crypto.random());

            try (CipherOutputStream oStream = new CipherOutputStream(cipherStream, cipher)) {

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
        throwIfArgIsNull(algorithm, ALGORITHM_PARAM);
        throwIfArgIsNull(key, KEY_PARAM);
        throwIfArgumentIsEmpty(iv, IV_PARAM);
        throwIfArgumentIsEmpty(data, DATA_PARAM);

        final Cipher cipher = crypto.primitive(algorithm);

        try {
            final AlgorithmParameterSpec parameterSpec = deriveParameters(algorithm, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec, crypto.random());

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
        throwIfArgIsNull(algorithm, ALGORITHM_PARAM);
        throwIfArgIsNull(key, KEY_PARAM);
        throwIfArgumentIsEmpty(iv, IV_PARAM);
        throwIfArgIsNull(buffer, BUFFER_PARAM);

        final Cipher cipher = crypto.primitive(algorithm);

        try {
            final AlgorithmParameterSpec parameterSpec = deriveParameters(algorithm, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec, crypto.random());

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
        throwIfArgIsNull(algorithm, ALGORITHM_PARAM);

        final int nonceSize = deriveNonceSize(algorithm);
        final byte[] nonce = new byte[nonceSize];
        final SecureRandom random = crypto.random();

        random.nextBytes(nonce);
        return nonce;
    }
}
