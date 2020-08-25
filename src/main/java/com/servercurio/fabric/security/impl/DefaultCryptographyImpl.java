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

import com.servercurio.fabric.security.Cryptography;
import com.servercurio.fabric.security.spi.DigestProvider;
import com.servercurio.fabric.security.spi.EncryptionProvider;
import com.servercurio.fabric.security.spi.MacProvider;
import com.servercurio.fabric.security.spi.PrimitiveProvider;
import com.servercurio.fabric.security.spi.SignatureProvider;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.ServiceLoader;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Positive;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import static com.servercurio.fabric.lang.Validators.throwIfArgIsNotPositive;
import static com.servercurio.fabric.lang.Validators.throwIfArgIsNull;

/**
 * Default {@link Cryptography} implementation provided by the base {@code Fabric} library.
 *
 * @author Nathan Klick
 * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html">Java
 *         Cryptography Architecture</a>
 */
public class DefaultCryptographyImpl implements Cryptography {

    /**
     * The default buffer size to use when reading/writing blocks of data from streams.
     */
    public static final int STREAM_BUFFER_SIZE = 8192;

    /**
     * The {@code stream} parameter name represented as a string value.
     */
    private static final String STREAM_PARAM = "stream";

    /**
     * The {@code fn} parameter name represented as a string value.
     */
    private static final String FN_PARAM = "fn";

    /**
     * The {@code blockSize} parameter name represented as a string value.
     */
    private static final String BLOCK_SIZE_PARAM = "blockSize";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * The {@link PrimitiveProvider} implementation to be used by this instance.
     */
    private final PrimitiveProvider primitiveProvider;


    /**
     * Private default constructor.
     */
    protected DefaultCryptographyImpl() {
        this.primitiveProvider = ServiceLoader.load(PrimitiveProvider.class)
                                              .findFirst().orElseGet(PrimitiveProviderImpl::new);
    }

    /**
     * Utility method that applies reads {@link #STREAM_BUFFER_SIZE} blocks from the {@code stream} parameter and
     * applies the {@code fn} lambda function to each block. This method will read from the stream until it reaches the
     * end of the stream.
     *
     * @param stream
     *         the input stream from which blocks are read, not null
     * @param fn
     *         the lambda function to be applied to each block, not null
     * @throws IOException
     *         if an error occurs while reading from the input stream
     * @throws GeneralSecurityException
     *         if an errors occurs while performing a cryptographic operation
     * @throws IllegalArgumentException
     *         if the {@code stream} or the {@code fn} parameters are null
     */
    public static void applyToStream(@NotNull final InputStream stream,
                                     @NotNull final TriConsumer<byte[], Integer, Integer> fn) throws
                                                                                              IOException,
                                                                                              GeneralSecurityException {
        applyToStream(stream, STREAM_BUFFER_SIZE, fn);
    }

    /**
     * Utility method that applies reads {@code blockSize} blocks from the {@code stream} parameter and applies the
     * {@code fn} lambda function to each block. This method will read from the stream until it reaches the end of the
     * stream.
     *
     * @param stream
     *         the input stream from which blocks are read, not null
     * @param blockSize
     *         the maximum size of each block to read, positive integer
     * @param fn
     *         the lambda function to be applied to each block, not null
     * @throws IOException
     *         if an error occurs while reading from the input stream
     * @throws GeneralSecurityException
     *         if an errors occurs while performing a cryptographic operation
     * @throws IllegalArgumentException
     *         if the {@code stream} or {@code fn} parameters are null or if the {@code blockSize} paramter is less than
     *         or equal to zero
     */
    public static void applyToStream(@NotNull final InputStream stream, @Positive final int blockSize,
                                     @NotNull final TriConsumer<byte[], Integer, Integer> fn) throws
                                                                                              IOException,
                                                                                              GeneralSecurityException {
        throwIfArgIsNull(stream, STREAM_PARAM);
        throwIfArgIsNotPositive(blockSize, BLOCK_SIZE_PARAM);
        throwIfArgIsNull(fn, FN_PARAM);

        final byte[] buffer = new byte[blockSize];

        int bytesRead = stream.readNBytes(buffer, 0, buffer.length);

        while (bytesRead > 0) {
            fn.apply(buffer, 0, bytesRead);
            bytesRead = stream.readNBytes(buffer, 0, buffer.length);
        }
    }

    /**
     * Factory method that creates a new instance on every invocation.
     *
     * @return a new {@linkplain Cryptography} instance, not null
     */
    public static Cryptography newInstance() {
        return new DefaultCryptographyImpl();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public DigestProvider digest() {
        return ServiceLoader.load(DigestProvider.class)
                            .findFirst()
                            .orElseGet(() -> new DigestProviderImpl(primitiveProvider));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public EncryptionProvider encryption() {
        return ServiceLoader.load(EncryptionProvider.class)
                            .findFirst()
                            .orElseGet(() -> new EncryptionProviderImpl(primitiveProvider));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public MacProvider mac() {
        return ServiceLoader.load(MacProvider.class)
                            .findFirst()
                            .orElseGet(() -> new MacProviderImpl(primitiveProvider));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public SignatureProvider signature() {
        return ServiceLoader.load(SignatureProvider.class)
                            .findFirst()
                            .orElseGet(() -> new SignatureProviderImpl(primitiveProvider));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public PrimitiveProvider primitives() {
        return primitiveProvider;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void close() {
        primitiveProvider.close();
    }


}
