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
import com.servercurio.fabric.security.Seal;
import com.servercurio.fabric.security.SignatureAlgorithm;
import com.servercurio.fabric.security.spi.SignatureProvider;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.concurrent.Future;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

import static com.servercurio.fabric.lang.Validators.throwIfArgumentIsEmpty;
import static com.servercurio.fabric.lang.Validators.throwIfArgIsNull;
import static com.servercurio.fabric.security.impl.DefaultCryptographyImpl.applyToStream;

/**
 * Default {@code Fabric Unified Cryptography API} provider implementation that encapsulates all of the available
 * message digest functionality. The default algorithm is {@link SignatureAlgorithm#RSA_SHA_384} which is the minimum
 * recommended algorithm that is C-NSA compliant.
 *
 * @author Nathan Klick
 * @see Cryptography
 * @see SignatureAlgorithm
 */
public class SignatureProviderImpl implements SignatureProvider {

    /**
     * The {@code crypto} field name represented as a string value.
     */
    private static final String CRYPTO_FIELD = "crypto";

    /**
     * The {@code algorithm} parameter name represented as a string value.
     */
    private static final String ALGORITHM_PARAM = "algorithm";

    /**
     * The {@code seal} parameter name represented as a string value.
     */
    private static final String SEAL_PARAM = "seal";

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
     * The {@linkplain Cryptography} implementation to which this provider is bound.
     */
    @NotNull
    private final DefaultCryptographyImpl crypto;

    /**
     * Constructs a new provider instance bound to the given {@link Cryptography} implementation.
     *
     * @param crypto
     *         the {@link DefaultCryptographyImpl} to which this provider is bound, not null
     */
    public SignatureProviderImpl(@NotNull final DefaultCryptographyImpl crypto) {
        throwIfArgIsNull(crypto, CRYPTO_FIELD);

        this.crypto = crypto;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Seal> signAsync(@NotNull final SignatureAlgorithm algorithm, @NotNull final PrivateKey key,
                                  @NotNull final InputStream stream) {
        return crypto.executorService().submit(() -> signSync(algorithm, key, stream));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Seal> signAsync(@NotNull final SignatureAlgorithm algorithm, @NotNull final PrivateKey key,
                                  @NotNull final byte[] data) {
        return crypto.executorService().submit(() -> signSync(algorithm, key, data));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Seal> signAsync(@NotNull final SignatureAlgorithm algorithm, @NotNull final PrivateKey key,
                                  @NotEmpty final Hash... hashes) {
        return crypto.executorService().submit(() -> signSync(algorithm, key, hashes));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Seal> signAsync(@NotNull final SignatureAlgorithm algorithm, @NotNull final PrivateKey key,
                                  @NotNull final ByteBuffer buffer) {
        return crypto.executorService().submit(() -> signSync(algorithm, key, buffer));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Seal signSync(@NotNull final SignatureAlgorithm algorithm, @NotNull final PrivateKey key,
                         @NotNull final InputStream stream) {
        throwIfArgIsNull(algorithm, ALGORITHM_PARAM);
        throwIfArgIsNull(key, KEY_PARAM);
        throwIfArgIsNull(stream, STREAM_PARAM);

        final Signature signature = crypto.primitive(algorithm);

        try {
            signature.initSign(key, crypto.random());
            applyToStream(stream, signature::update);

            return new Seal(algorithm, signature.sign());
        } catch (IOException | GeneralSecurityException ex) {
            throw new CryptographyException(ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Seal signSync(@NotNull final SignatureAlgorithm algorithm, @NotNull final PrivateKey key,
                         @NotNull final byte[] data) {
        throwIfArgIsNull(algorithm, ALGORITHM_PARAM);
        throwIfArgIsNull(key, KEY_PARAM);
        throwIfArgIsNull(data, DATA_PARAM);

        final Signature signature = crypto.primitive(algorithm);

        try {
            signature.initSign(key, crypto.random());
            signature.update(data);
            return new Seal(algorithm, signature.sign());
        } catch (SignatureException | InvalidKeyException ex) {
            throw new CryptographyException(ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Seal signSync(@NotNull final SignatureAlgorithm algorithm, @NotNull final PrivateKey key,
                         @NotEmpty final Hash... hashes) {
        throwIfArgIsNull(algorithm, ALGORITHM_PARAM);
        throwIfArgIsNull(key, KEY_PARAM);
        throwIfArgumentIsEmpty(hashes, HASHES_PARAM);

        final Signature signature = crypto.primitive(algorithm);

        try {
            signature.initSign(key, crypto.random());

            for (final Hash hash : hashes) {
                if (hash != null) {
                    signature.update(hash.getValue());
                } else {
                    signature.update(Hash.EMPTY.getValue());
                }
            }

            return new Seal(algorithm, signature.sign());
        } catch (SignatureException | InvalidKeyException ex) {
            throw new CryptographyException(ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Seal signSync(@NotNull final SignatureAlgorithm algorithm, @NotNull final PrivateKey key,
                         @NotNull final ByteBuffer buffer) {
        throwIfArgIsNull(algorithm, ALGORITHM_PARAM);
        throwIfArgIsNull(key, KEY_PARAM);
        throwIfArgIsNull(buffer, BUFFER_PARAM);

        final Signature signature = crypto.primitive(algorithm);

        try {
            signature.initSign(key, crypto.random());
            signature.update(buffer);
            return new Seal(algorithm, signature.sign());
        } catch (SignatureException | InvalidKeyException ex) {
            throw new CryptographyException(ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Boolean> verifyAsync(@NotNull final Seal seal, @NotNull final PublicKey key,
                                       @NotNull final InputStream stream) {
        return crypto.executorService().submit(() -> verifySync(seal, key, stream));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Boolean> verifyAsync(@NotNull final Seal seal, @NotNull final PublicKey key,
                                       @NotNull final byte[] data) {
        return crypto.executorService().submit(() -> verifySync(seal, key, data));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Boolean> verifyAsync(@NotNull final Seal seal, @NotNull final PublicKey key,
                                       @NotEmpty final Hash... hashes) {
        return crypto.executorService().submit(() -> verifySync(seal, key, hashes));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Boolean> verifyAsync(@NotNull final Seal seal, @NotNull final PublicKey key,
                                       @NotNull final ByteBuffer buffer) {
        return crypto.executorService().submit(() -> verifySync(seal, key, buffer));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean verifySync(@NotNull final Seal seal, @NotNull final PublicKey key,
                              @NotNull final InputStream stream) {
        throwIfArgIsNull(seal, SEAL_PARAM);
        throwIfArgIsNull(key, KEY_PARAM);
        throwIfArgIsNull(stream, STREAM_PARAM);

        final Signature signature = crypto.primitive(seal.getAlgorithm());

        try {
            signature.initVerify(key);
            applyToStream(stream, signature::update);

            return signature.verify(seal.getValue());
        } catch (IOException | GeneralSecurityException ex) {
            throw new CryptographyException(ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean verifySync(@NotNull final Seal seal, @NotNull final PublicKey key, @NotNull final byte[] data) {
        throwIfArgIsNull(seal, SEAL_PARAM);
        throwIfArgIsNull(key, KEY_PARAM);
        throwIfArgIsNull(data, DATA_PARAM);

        final Signature signature = crypto.primitive(seal.getAlgorithm());

        try {
            signature.initVerify(key);
            signature.update(data);
            return signature.verify(seal.getValue());
        } catch (InvalidKeyException | SignatureException ex) {
            throw new CryptographyException(ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean verifySync(@NotNull final Seal seal, @NotNull final PublicKey key, @NotEmpty final Hash... hashes) {
        throwIfArgIsNull(seal, SEAL_PARAM);
        throwIfArgIsNull(key, KEY_PARAM);
        throwIfArgumentIsEmpty(hashes, HASHES_PARAM);

        final Signature signature = crypto.primitive(seal.getAlgorithm());

        try {
            signature.initVerify(key);

            for (final Hash hash : hashes) {
                if (hash != null) {
                    signature.update(hash.getValue());
                } else {
                    signature.update(Hash.EMPTY.getValue());
                }
            }

            return signature.verify(seal.getValue());
        } catch (InvalidKeyException | SignatureException ex) {
            throw new CryptographyException(ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean verifySync(@NotNull final Seal seal, @NotNull final PublicKey key,
                              @NotNull final ByteBuffer buffer) {
        throwIfArgIsNull(seal, SEAL_PARAM);
        throwIfArgIsNull(key, KEY_PARAM);
        throwIfArgIsNull(buffer, BUFFER_PARAM);

        final Signature signature = crypto.primitive(seal.getAlgorithm());

        try {
            signature.initVerify(key);
            signature.update(buffer);
            return signature.verify(seal.getValue());
        } catch (InvalidKeyException | SignatureException ex) {
            throw new CryptographyException(ex);
        }
    }
}
