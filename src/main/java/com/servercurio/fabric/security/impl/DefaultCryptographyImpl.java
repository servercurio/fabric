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

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.HashMap;

public final class DefaultCryptographyImpl implements Cryptography, AutoCloseable {

    private static final DefaultCryptographyImpl INSTANCE = new DefaultCryptographyImpl();

    private static final int STREAM_BUFFER_SIZE = 8192;

    private static final ThreadLocal<HashMap<HashAlgorithm, MessageDigest>> hashAlgorithmCache = ThreadLocal
            .withInitial(HashMap::new);

    private DefaultCryptographyImpl() {

    }

    public static ThreadLocal<HashMap<HashAlgorithm, MessageDigest>> getHashAlgorithmCache() {
        return hashAlgorithmCache;
    }

    public static Cryptography getInstance() {
        return INSTANCE;
    }

    private static MessageDigest acquireAlgorithm(final HashAlgorithm algorithm) {
        final HashMap<HashAlgorithm, MessageDigest> cache = hashAlgorithmCache.get();

        if (!cache.containsKey(algorithm)) {
            cache.put(algorithm, algorithm.instance());
        }

        return cache.get(algorithm);
    }

    /**
     * Closes this resource, relinquishing any underlying resources. This method is invoked automatically on objects
     * managed by the {@code try}-with-resources statement.
     *
     * <p>While this interface method is declared to throw {@code
     * Exception}, implementers are <em>strongly</em> encouraged to declare concrete implementations of the {@code
     * close} method to throw more specific exceptions, or to throw no exception at all if the close operation cannot
     * fail.
     *
     * <p> Cases where the close operation may fail require careful
     * attention by implementers. It is strongly advised to relinquish the underlying resources and to internally
     * <em>mark</em> the resource as closed, prior to throwing the exception. The {@code close} method is unlikely to
     * be invoked more than once and so this ensures that the resources are released in a timely manner. Furthermore it
     * reduces problems that could arise when the resource wraps, or is wrapped, by another resource.
     *
     * <p><em>Implementers of this interface are also strongly advised
     * to not have the {@code close} method throw {@link InterruptedException}.</em>
     * <p>
     * This exception interacts with a thread's interrupted status, and runtime misbehavior is likely to occur if an
     * {@code InterruptedException} is {@linkplain Throwable#addSuppressed suppressed}.
     * <p>
     * More generally, if it would cause problems for an exception to be suppressed, the {@code AutoCloseable.close}
     * method should not throw it.
     *
     * <p>Note that unlike the {@link Closeable#close close}
     * method of {@link Closeable}, this {@code close} method is <em>not</em> required to be idempotent.  In other
     * words, calling this {@code close} method more than once may have some visible side effect, unlike {@code
     * Closeable.close} which is required to have no effect if called more than once.
     * <p>
     * However, implementers of this interface are strongly encouraged to make their {@code close} methods idempotent.
     */
    @Override
    public void close() {
        hashAlgorithmCache.remove();
    }

    @Override
    public Hash digestSync(final InputStream stream) {
        return digestSync(stream, HashAlgorithm.SHA_384);
    }

    @Override
    public Hash digestSync(final InputStream stream, final HashAlgorithm algorithm) {
        final MessageDigest digest = acquireAlgorithm(algorithm);
        final byte[] buffer = new byte[STREAM_BUFFER_SIZE];

        try {
            int bytesRead = stream.readNBytes(buffer, 0, buffer.length);

            while (bytesRead > 0) {
                digest.update(buffer, 0, bytesRead);
                bytesRead = stream.readNBytes(buffer, 0, buffer.length);
            }
        } catch (IOException ex) {
            throw new CryptographyException(ex);
        }

        return new Hash(algorithm, digest.digest());
    }

    @Override
    public Hash digestSync(final byte[] data) {
        return digestSync(data, HashAlgorithm.SHA_384);
    }

    @Override
    public Hash digestSync(final byte[] data, final HashAlgorithm algorithm) {
        final MessageDigest digest = acquireAlgorithm(algorithm);

        digest.update(data);
        return new Hash(algorithm, digest.digest());
    }

    @Override
    public Hash digestSync(final Hash leftHash, final Hash rightHash) {
        return digestSync(leftHash, rightHash, HashAlgorithm.SHA_384);
    }

    @Override
    public Hash digestSync(final Hash leftHash, final Hash rightHash, final HashAlgorithm algorithm) {
        final MessageDigest digest = acquireAlgorithm(algorithm);

        if (leftHash != null) {
            digest.update(leftHash.getValue());
        } else {
            digest.update(Hash.EMPTY.getValue());
        }

        if (rightHash != null) {
            digest.update(rightHash.getValue());
        } else {
            digest.update(Hash.EMPTY.getValue());
        }

        return new Hash(algorithm, digest.digest());
    }

    @Override
    public Hash digestSync(final ByteBuffer buffer) {
        return digestSync(buffer, HashAlgorithm.SHA_384);
    }

    @Override
    public Hash digestSync(final ByteBuffer buffer, final HashAlgorithm algorithm) {
        final MessageDigest digest = acquireAlgorithm(algorithm);

        digest.update(buffer);
        return new Hash(algorithm, digest.digest());
    }
}
