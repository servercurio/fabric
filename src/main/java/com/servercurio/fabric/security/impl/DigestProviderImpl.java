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
import com.servercurio.fabric.security.HashAlgorithm;
import com.servercurio.fabric.security.spi.DigestProvider;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.concurrent.Future;

import static com.servercurio.fabric.security.impl.DefaultCryptographyImpl.applyToStream;

public class DigestProviderImpl implements DigestProvider {

    private final DefaultCryptographyImpl crypto;

    public DigestProviderImpl(final DefaultCryptographyImpl crypto) {
        this.crypto = crypto;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Hash> digestAsync(final HashAlgorithm algorithm, final InputStream stream) {
        return crypto.executorService().submit(() -> digestSync(algorithm, stream));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Hash> digestAsync(final HashAlgorithm algorithm, final byte[] data) {
        return crypto.executorService().submit(() -> digestSync(algorithm, data));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Hash> digestAsync(final HashAlgorithm algorithm, final Hash... hashes) {
        return crypto.executorService().submit(() -> digestSync(algorithm, hashes));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Hash> digestAsync(final HashAlgorithm algorithm, final ByteBuffer buffer) {
        return crypto.executorService().submit(() -> digestSync(algorithm, buffer));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Hash digestSync(final HashAlgorithm algorithm, final InputStream stream) {
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
    public Hash digestSync(final HashAlgorithm algorithm, final byte[] data) {
        final MessageDigest digest = crypto.primitive(algorithm);

        digest.update(data);
        return new Hash(algorithm, digest.digest());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Hash digestSync(final HashAlgorithm algorithm, final Hash... hashes) {
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
    public Hash digestSync(final HashAlgorithm algorithm, final ByteBuffer buffer) {
        final MessageDigest digest = crypto.primitive(algorithm);

        digest.update(buffer);
        return new Hash(algorithm, digest.digest());
    }

}
