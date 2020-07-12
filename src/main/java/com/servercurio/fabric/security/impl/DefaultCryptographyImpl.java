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

import com.servercurio.fabric.security.CipherTransformation;
import com.servercurio.fabric.security.Cryptography;
import com.servercurio.fabric.security.CryptographyException;
import com.servercurio.fabric.security.Hash;
import com.servercurio.fabric.security.HashAlgorithm;
import com.servercurio.fabric.security.MacAlgorithm;
import com.servercurio.fabric.security.SignatureAlgorithm;
import com.servercurio.fabric.security.spi.CryptoPrimitiveSupplier;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.HashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import javax.crypto.Cipher;
import javax.crypto.Mac;

public final class DefaultCryptographyImpl implements Cryptography, AutoCloseable {

    private static final DefaultCryptographyImpl INSTANCE = new DefaultCryptographyImpl();

    private static final int STREAM_BUFFER_SIZE = 8192;

    private static final ThreadLocal<HashMap<HashAlgorithm, MessageDigest>> hashAlgorithmCache = ThreadLocal
            .withInitial(HashMap::new);

    private static final ThreadLocal<HashMap<SignatureAlgorithm, Signature>> signatureAlgorithmCache = ThreadLocal
            .withInitial(HashMap::new);

    private static final ThreadLocal<HashMap<CipherTransformation, Cipher>> cipherAlgorithmCache = ThreadLocal
            .withInitial(HashMap::new);

    private static final ThreadLocal<HashMap<MacAlgorithm, Mac>> macAlgorithmCache = ThreadLocal
            .withInitial(HashMap::new);

    private final ExecutorService executorService;

    /**
     *
     */
    private DefaultCryptographyImpl() {
        this.executorService = Executors.newCachedThreadPool();
    }

    public static Cryptography getInstance() {
        return INSTANCE;
    }

    public static Cryptography newInstance() {
        return new DefaultCryptographyImpl();
    }

    protected static ThreadLocal<HashMap<CipherTransformation, Cipher>> getCipherAlgorithmCache() {
        return cipherAlgorithmCache;
    }

    protected static ThreadLocal<HashMap<HashAlgorithm, MessageDigest>> getHashAlgorithmCache() {
        return hashAlgorithmCache;
    }

    protected static ThreadLocal<HashMap<MacAlgorithm, Mac>> getMacAlgorithmCache() {
        return macAlgorithmCache;
    }

    protected static ThreadLocal<HashMap<SignatureAlgorithm, Signature>> getSignatureAlgorithmCache() {
        return signatureAlgorithmCache;
    }

    private static <T, E extends CryptoPrimitiveSupplier<T>> T acquireAlgorithm(final E algorithm,
                                                                                final ThreadLocal<HashMap<E, T>> threadLocal) {
        final HashMap<E, T> cache = threadLocal.get();

        if (!cache.containsKey(algorithm)) {
            cache.put(algorithm, algorithm.instance());
        }

        return cache.get(algorithm);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Cipher acquirePrimitive(final CipherTransformation algorithm) {
        return acquireAlgorithm(algorithm, cipherAlgorithmCache);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Signature acquirePrimitive(final SignatureAlgorithm algorithm) {
        return acquireAlgorithm(algorithm, signatureAlgorithmCache);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public MessageDigest acquirePrimitive(final HashAlgorithm algorithm) {
        return acquireAlgorithm(algorithm, hashAlgorithmCache);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Mac acquirePrimitive(final MacAlgorithm algorithm) {
        return acquireAlgorithm(algorithm, macAlgorithmCache);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Hash> authenticateAsync(final Key key, final InputStream stream, final MacAlgorithm algorithm) {
        return executorService.submit(() -> authenticateSync(key, stream, algorithm));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Hash> authenticateAsync(final Key key, final byte[] data, final MacAlgorithm algorithm) {
        return executorService.submit(() -> authenticateSync(key, data, algorithm));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Hash> authenticateAsync(final Key key, final Hash leftHash, final Hash rightHash,
                                          final MacAlgorithm algorithm) {
        return executorService.submit(() -> authenticateSync(key, leftHash, rightHash, algorithm));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Hash> authenticateAsync(final Key key, final ByteBuffer buffer, final MacAlgorithm algorithm) {
        return executorService.submit(() -> authenticateSync(key, buffer, algorithm));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Hash authenticateSync(final Key key, final InputStream stream, final MacAlgorithm algorithm) {
        final Mac mac = acquirePrimitive(algorithm);
        final byte[] buffer = new byte[STREAM_BUFFER_SIZE];

        try {
            mac.init(key);
            int bytesRead = stream.readNBytes(buffer, 0, buffer.length);

            while (bytesRead > 0) {
                mac.update(buffer, 0, bytesRead);
                bytesRead = stream.readNBytes(buffer, 0, buffer.length);
            }
        } catch (IOException | InvalidKeyException ex) {
            throw new CryptographyException(ex);
        }

        return new Hash(algorithm.hashAlgorithm(), mac.doFinal());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Hash authenticateSync(final Key key, final byte[] data, final MacAlgorithm algorithm) {
        final Mac mac = acquirePrimitive(algorithm);
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
    public Hash authenticateSync(final Key key, final Hash leftHash, final Hash rightHash,
                                 final MacAlgorithm algorithm) {
        final Mac mac = acquirePrimitive(algorithm);

        try {
            mac.init(key);

            if (leftHash != null) {
                mac.update(leftHash.getValue());
            } else {
                mac.update(Hash.EMPTY.getValue());
            }

            if (rightHash != null) {
                mac.update(rightHash.getValue());
            } else {
                mac.update(Hash.EMPTY.getValue());
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
    public Hash authenticateSync(final Key key, final ByteBuffer buffer, final MacAlgorithm algorithm) {
        final Mac mac = acquirePrimitive(algorithm);
        try {
            mac.init(key);
            mac.update(buffer);
            return new Hash(algorithm.hashAlgorithm(), mac.doFinal());
        } catch (InvalidKeyException ex) {
            throw new CryptographyException(ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void close() {
        executorService.shutdownNow();
        hashAlgorithmCache.remove();
        macAlgorithmCache.remove();
        cipherAlgorithmCache.remove();
        signatureAlgorithmCache.remove();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Hash> digestAsync(final InputStream stream, final HashAlgorithm algorithm) {
        return executorService.submit(() -> digestSync(stream, algorithm));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Hash> digestAsync(final byte[] data, final HashAlgorithm algorithm) {
        return executorService.submit(() -> digestSync(data, algorithm));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Hash> digestAsync(final Hash leftHash, final Hash rightHash, final HashAlgorithm algorithm) {
        return executorService.submit(() -> digestSync(leftHash, rightHash, algorithm));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Future<Hash> digestAsync(final ByteBuffer buffer, final HashAlgorithm algorithm) {
        return executorService.submit(() -> digestSync(buffer, algorithm));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Hash digestSync(final InputStream stream, final HashAlgorithm algorithm) {
        final MessageDigest digest = acquirePrimitive(algorithm);
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

    /**
     * {@inheritDoc}
     */
    @Override
    public Hash digestSync(final byte[] data, final HashAlgorithm algorithm) {
        final MessageDigest digest = acquirePrimitive(algorithm);

        digest.update(data);
        return new Hash(algorithm, digest.digest());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Hash digestSync(final Hash leftHash, final Hash rightHash, final HashAlgorithm algorithm) {
        final MessageDigest digest = acquirePrimitive(algorithm);

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

    /**
     * {@inheritDoc}
     */
    @Override
    public Hash digestSync(final ByteBuffer buffer, final HashAlgorithm algorithm) {
        final MessageDigest digest = acquirePrimitive(algorithm);

        digest.update(buffer);
        return new Hash(algorithm, digest.digest());
    }


}
