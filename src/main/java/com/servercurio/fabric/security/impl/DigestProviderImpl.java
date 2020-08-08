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
import com.servercurio.fabric.security.CryptographyException;
import com.servercurio.fabric.security.Hash;
import com.servercurio.fabric.security.HashAlgorithm;
import com.servercurio.fabric.security.spi.DigestProvider;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.concurrent.Future;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

import static com.servercurio.fabric.lang.Validators.throwIfArgumentIsEmpty;
import static com.servercurio.fabric.lang.Validators.throwIfArgumentIsNull;
import static com.servercurio.fabric.security.impl.DefaultCryptographyImpl.applyToStream;

/**
 * Default {@code Fabric Unified Cryptography API} provider implementation that encapsulates all of the available
 * message digest functionality. The default algorithm is {@link HashAlgorithm#SHA_384} which is the minimum recommended
 * algorithm that is C-NSA compliant.
 *
 * @author Nathan Klick
 * @see Cryptography
 * @see HashAlgorithm
 */
public class DigestProviderImpl implements DigestProvider {

    /**
     * The {@code crypto} field name represented as a string value.
     */
    private static final String CRYPTO_FIELD = "crypto";

    /**
     * The {@code algorithm} parameter name represented as a string value.
     */
    private static final String ALGORITHM_PARAM = "algorithm";

    /**
     * The {@code stream} parameter name represented as a string value.
     */
    private static final String STREAM_PARAM = "stream";

    /**
     * The {@code hashes} parameter name represented as a string value.
     */
    private static final String HASHES_PARAM = "hashes";

    /**
     * The {@code data} parameter name represented as a string value.
     */
    private static final String DATA_PARAM = "data";

    /**
     * The {@code buffer} parameter name represented as a string value.
     */
    private static final String BUFFER_PARAM = "buffer";

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
    public DigestProviderImpl(@NotNull final DefaultCryptographyImpl crypto) {
        throwIfArgumentIsNull(crypto, CRYPTO_FIELD);

        this.crypto = crypto;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Hash> digestAsync(@NotNull final HashAlgorithm algorithm, @NotNull final InputStream stream) {
        return crypto.executorService().submit(() -> digestSync(algorithm, stream));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Hash> digestAsync(@NotNull final HashAlgorithm algorithm, @NotNull final byte[] data) {
        return crypto.executorService().submit(() -> digestSync(algorithm, data));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Hash> digestAsync(@NotNull final HashAlgorithm algorithm, @NotEmpty final Hash... hashes) {
        return crypto.executorService().submit(() -> digestSync(algorithm, hashes));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Hash> digestAsync(@NotNull final HashAlgorithm algorithm, @NotNull final ByteBuffer buffer) {
        return crypto.executorService().submit(() -> digestSync(algorithm, buffer));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Hash digestSync(@NotNull final HashAlgorithm algorithm, @NotNull final InputStream stream) {
        throwIfArgumentIsNull(algorithm, ALGORITHM_PARAM);
        throwIfArgumentIsNull(stream, STREAM_PARAM);

        final MessageDigest digest = crypto.primitive(algorithm);

        try {
            applyToStream(stream, digest::update);
        } catch (IOException | GeneralSecurityException ex) {
            throw new CryptographyException(ex);
        }

        return new Hash(algorithm, digest.digest());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Hash digestSync(@NotNull final HashAlgorithm algorithm, @NotNull final byte[] data) {
        throwIfArgumentIsNull(algorithm, ALGORITHM_PARAM);
        throwIfArgumentIsNull(data, DATA_PARAM);

        final MessageDigest digest = crypto.primitive(algorithm);

        digest.update(data);
        return new Hash(algorithm, digest.digest());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Hash digestSync(@NotNull final HashAlgorithm algorithm, @NotEmpty final Hash... hashes) {
        throwIfArgumentIsNull(algorithm, ALGORITHM_PARAM);
        throwIfArgumentIsEmpty(hashes, HASHES_PARAM);

        final MessageDigest digest = crypto.primitive(algorithm);

        for (final Hash hash : hashes) {
            if (hash != null) {
                digest.update(hash.getValue());
            } else {
                digest.update(Hash.EMPTY.getValue());
            }
        }

        return new Hash(algorithm, digest.digest());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Hash digestSync(@NotNull final HashAlgorithm algorithm, @NotNull final ByteBuffer buffer) {
        throwIfArgumentIsNull(algorithm, ALGORITHM_PARAM);
        throwIfArgumentIsNull(buffer, BUFFER_PARAM);

        final MessageDigest digest = crypto.primitive(algorithm);

        digest.update(buffer);
        return new Hash(algorithm, digest.digest());
    }

}
