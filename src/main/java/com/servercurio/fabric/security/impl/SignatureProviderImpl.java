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

import static com.servercurio.fabric.security.impl.DefaultCryptographyImpl.applyToStream;

public class SignatureProviderImpl implements SignatureProvider {

    private final DefaultCryptographyImpl crypto;

    public SignatureProviderImpl(final DefaultCryptographyImpl crypto) {
        this.crypto = crypto;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Seal> signAsync(final SignatureAlgorithm algorithm, final PrivateKey key, final InputStream stream) {
        return crypto.executorService().submit(() -> signSync(algorithm, key, stream));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Seal> signAsync(final SignatureAlgorithm algorithm, final PrivateKey key, final byte[] data) {
        return crypto.executorService().submit(() -> signSync(algorithm, key, data));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Seal> signAsync(final SignatureAlgorithm algorithm, final PrivateKey key, final Hash... hashes) {
        return crypto.executorService().submit(() -> signSync(algorithm, key, hashes));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Seal> signAsync(final SignatureAlgorithm algorithm, final PrivateKey key, final ByteBuffer buffer) {
        return crypto.executorService().submit(() -> signSync(algorithm, key, buffer));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Seal signSync(final SignatureAlgorithm algorithm, final PrivateKey key, final InputStream stream) {
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
    public Seal signSync(final SignatureAlgorithm algorithm, final PrivateKey key, final byte[] data) {
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
    public Seal signSync(final SignatureAlgorithm algorithm, final PrivateKey key, final Hash... hashes) {
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
    public Seal signSync(final SignatureAlgorithm algorithm, final PrivateKey key, final ByteBuffer buffer) {
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
    public Future<Boolean> verifyAsync(final Seal seal, final PublicKey key, final InputStream stream) {
        return crypto.executorService().submit(() -> verifySync(seal, key, stream));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Boolean> verifyAsync(final Seal seal, final PublicKey key, final byte[] data) {
        return crypto.executorService().submit(() -> verifySync(seal, key, data));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Boolean> verifyAsync(final Seal seal, final PublicKey key, final Hash... hashes) {
        return crypto.executorService().submit(() -> verifySync(seal, key, hashes));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Boolean> verifyAsync(final Seal seal, final PublicKey key, final ByteBuffer buffer) {
        return crypto.executorService().submit(() -> verifySync(seal, key, buffer));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean verifySync(final Seal seal, final PublicKey key, final InputStream stream) {
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
    public boolean verifySync(final Seal seal, final PublicKey key, final byte[] data) {
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
    public boolean verifySync(final Seal seal, final PublicKey key, final Hash... hashes) {
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
    public boolean verifySync(final Seal seal, final PublicKey key, final ByteBuffer buffer) {
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
