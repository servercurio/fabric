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

import static com.servercurio.fabric.security.impl.DefaultCryptographyImpl.applyToStream;

public class MacProviderImpl implements MacProvider {

    private final DefaultCryptographyImpl crypto;

    public MacProviderImpl(final DefaultCryptographyImpl crypto) {
        this.crypto = crypto;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Hash> authenticateAsync(final MacAlgorithm algorithm, final Key key, final InputStream stream) {
        return crypto.executorService().submit(() -> authenticateSync(algorithm, key, stream));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Hash> authenticateAsync(final MacAlgorithm algorithm, final Key key, final byte[] data) {
        return crypto.executorService().submit(() -> authenticateSync(algorithm, key, data));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Hash> authenticateAsync(final MacAlgorithm algorithm, final Key key, final Hash... hashes) {
        return crypto.executorService().submit(() -> authenticateSync(algorithm, key, hashes));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Hash> authenticateAsync(final MacAlgorithm algorithm, final Key key, final ByteBuffer buffer) {
        return crypto.executorService().submit(() -> authenticateSync(algorithm, key, buffer));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Hash authenticateSync(final MacAlgorithm algorithm, final Key key, final InputStream stream) {
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
    public Hash authenticateSync(final MacAlgorithm algorithm, final Key key, final byte[] data) {
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
    public Hash authenticateSync(final MacAlgorithm algorithm, final Key key, final Hash... hashes) {
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
    public Hash authenticateSync(final MacAlgorithm algorithm, final Key key, final ByteBuffer buffer) {
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
