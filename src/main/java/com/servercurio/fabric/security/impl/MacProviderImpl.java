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
import com.servercurio.fabric.security.MacAlgorithm;
import com.servercurio.fabric.security.spi.MacProvider;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.util.concurrent.Future;
import javax.crypto.Mac;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

import static com.servercurio.fabric.lang.Validators.throwIfArgumentIsEmpty;
import static com.servercurio.fabric.lang.Validators.throwIfArgIsNull;
import static com.servercurio.fabric.security.impl.DefaultCryptographyImpl.applyToStream;

/**
 * Default {@code Fabric Unified Cryptography API} provider implementation that encapsulates all of the available
 * message digest functionality. The default algorithm is {@link MacAlgorithm#HMAC_SHA_384} which is the minimum
 * recommended algorithm that is C-NSA compliant.
 *
 * @author Nathan Klick
 * @see Cryptography
 * @see MacAlgorithm
 */
public class MacProviderImpl implements MacProvider {

    /**
     * The {@code crypto} field name represented as a string value.
     */
    private static final String CRYPTO_FIELD = "crypto";

    /**
     * The {@code algorithm} parameter name represented as a string value.
     */
    private static final String ALGORITHM_PARAM = "algorithm";

    /**
     * The {@code key} parameter name represented as a string value.
     */
    private static final String KEY_PARAM = "key";

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
    public MacProviderImpl(@NotNull final DefaultCryptographyImpl crypto) {
        throwIfArgIsNull(crypto, CRYPTO_FIELD);

        this.crypto = crypto;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Hash> authenticateAsync(@NotNull final MacAlgorithm algorithm, @NotNull final Key key,
                                          @NotNull final InputStream stream) {
        return crypto.executorService().submit(() -> authenticateSync(algorithm, key, stream));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Hash> authenticateAsync(@NotNull final MacAlgorithm algorithm, @NotNull final Key key,
                                          @NotNull final byte[] data) {
        return crypto.executorService().submit(() -> authenticateSync(algorithm, key, data));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Hash> authenticateAsync(@NotNull final MacAlgorithm algorithm, @NotNull final Key key,
                                          @NotEmpty final Hash... hashes) {
        return crypto.executorService().submit(() -> authenticateSync(algorithm, key, hashes));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Hash> authenticateAsync(@NotNull final MacAlgorithm algorithm, @NotNull final Key key,
                                          @NotNull final ByteBuffer buffer) {
        return crypto.executorService().submit(() -> authenticateSync(algorithm, key, buffer));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Hash authenticateSync(@NotNull final MacAlgorithm algorithm, @NotNull final Key key,
                                 @NotNull final InputStream stream) {
        throwIfArgIsNull(algorithm, ALGORITHM_PARAM);
        throwIfArgIsNull(key, KEY_PARAM);
        throwIfArgIsNull(stream, STREAM_PARAM);

        final Mac mac = crypto.primitive(algorithm);

        try {
            mac.init(key);
            applyToStream(stream, mac::update);
        } catch (IOException | GeneralSecurityException ex) {
            throw new CryptographyException(ex);
        }

        return new Hash(algorithm.hashAlgorithm(), mac.doFinal());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Hash authenticateSync(@NotNull final MacAlgorithm algorithm, @NotNull final Key key,
                                 @NotNull final byte[] data) {
        throwIfArgIsNull(algorithm, ALGORITHM_PARAM);
        throwIfArgIsNull(key, KEY_PARAM);
        throwIfArgIsNull(data, DATA_PARAM);

        final Mac mac = crypto.primitive(algorithm);

        try {
            mac.init(key);
            mac.update(data);
            return new Hash(algorithm.hashAlgorithm(), mac.doFinal());
        } catch (InvalidKeyException ex) {
            throw new CryptographyException(ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Hash authenticateSync(@NotNull final MacAlgorithm algorithm, @NotNull final Key key,
                                 @NotEmpty final Hash... hashes) {
        throwIfArgIsNull(algorithm, ALGORITHM_PARAM);
        throwIfArgIsNull(key, KEY_PARAM);
        throwIfArgumentIsEmpty(hashes, HASHES_PARAM);

        final Mac mac = crypto.primitive(algorithm);

        try {
            mac.init(key);

            for (final Hash hash : hashes) {
                if (hash != null) {
                    mac.update(hash.getValue());
                } else {
                    mac.update(Hash.EMPTY.getValue());
                }
            }

            return new Hash(algorithm.hashAlgorithm(), mac.doFinal());
        } catch (InvalidKeyException ex) {
            throw new CryptographyException(ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Hash authenticateSync(@NotNull final MacAlgorithm algorithm, @NotNull final Key key,
                                 @NotNull final ByteBuffer buffer) {
        throwIfArgIsNull(algorithm, ALGORITHM_PARAM);
        throwIfArgIsNull(key, KEY_PARAM);
        throwIfArgIsNull(buffer, BUFFER_PARAM);

        final Mac mac = crypto.primitive(algorithm);

        try {
            mac.init(key);
            mac.update(buffer);
            return new Hash(algorithm.hashAlgorithm(), mac.doFinal());
        } catch (InvalidKeyException ex) {
            throw new CryptographyException(ex);
        }
    }
}
