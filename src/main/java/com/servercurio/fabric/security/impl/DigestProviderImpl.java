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
import com.servercurio.fabric.security.spi.PrimitiveProvider;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.concurrent.Future;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

import static com.servercurio.fabric.lang.Validators.throwIfArgIsNull;
import static com.servercurio.fabric.lang.Validators.throwIfArgumentIsEmpty;
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
     * The {@code primitiveProvider} field name represented as a string value.
     */
    private static final String PRIMITIVE_PROVIDER_FIELD = "primitiveProvider";

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
     * The {@link PrimitiveProvider} implementation to which this provider is bound.
     */
    @NotNull
    private final PrimitiveProvider primitiveProvider;

    /**
     * Constructs a new provider instance bound to the given {@link Cryptography} implementation.
     *
     * @param primitiveProvider
     *         the {@link PrimitiveProvider} to which this provider is bound, not null
     */
    public DigestProviderImpl(@NotNull final PrimitiveProvider primitiveProvider) {
        throwIfArgIsNull(primitiveProvider, PRIMITIVE_PROVIDER_FIELD);

        this.primitiveProvider = primitiveProvider;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Hash> digestAsync(@NotNull final HashAlgorithm algorithm, @NotNull final InputStream stream) {
        return primitiveProvider.executorService().submit(() -> digestSync(algorithm, stream));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Hash> digestAsync(@NotNull final HashAlgorithm algorithm, @NotNull final byte[] data) {
        return primitiveProvider.executorService().submit(() -> digestSync(algorithm, data));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Hash> digestAsync(@NotNull final HashAlgorithm algorithm, @NotEmpty final Hash... hashes) {
        return primitiveProvider.executorService().submit(() -> digestSync(algorithm, hashes));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Hash> digestAsync(@NotNull final HashAlgorithm algorithm, @NotNull final ByteBuffer buffer) {
        return primitiveProvider.executorService().submit(() -> digestSync(algorithm, buffer));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Hash digestSync(@NotNull final HashAlgorithm algorithm, @NotNull final InputStream stream) {
        throwIfArgIsNull(algorithm, ALGORITHM_PARAM);
        throwIfArgIsNull(stream, STREAM_PARAM);

        final MessageDigest digest = primitiveProvider.primitive(algorithm);

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
        throwIfArgIsNull(algorithm, ALGORITHM_PARAM);
        throwIfArgIsNull(data, DATA_PARAM);

        final MessageDigest digest = primitiveProvider.primitive(algorithm);

        digest.update(data);
        return new Hash(algorithm, digest.digest());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Hash digestSync(@NotNull final HashAlgorithm algorithm, @NotEmpty final Hash... hashes) {
        throwIfArgIsNull(algorithm, ALGORITHM_PARAM);
        throwIfArgumentIsEmpty(hashes, HASHES_PARAM);

        final MessageDigest digest = primitiveProvider.primitive(algorithm);

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
        throwIfArgIsNull(algorithm, ALGORITHM_PARAM);
        throwIfArgIsNull(buffer, BUFFER_PARAM);

        final MessageDigest digest = primitiveProvider.primitive(algorithm);

        digest.update(buffer);
        return new Hash(algorithm, digest.digest());
    }

}
