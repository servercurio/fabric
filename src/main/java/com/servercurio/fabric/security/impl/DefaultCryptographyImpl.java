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
import com.servercurio.fabric.security.HashAlgorithm;
import com.servercurio.fabric.security.MacAlgorithm;
import com.servercurio.fabric.security.SignatureAlgorithm;
import com.servercurio.fabric.security.spi.CryptoPrimitiveSupplier;
import com.servercurio.fabric.security.spi.DigestProvider;
import com.servercurio.fabric.security.spi.EncryptionProvider;
import com.servercurio.fabric.security.spi.MacProvider;
import com.servercurio.fabric.security.spi.SignatureProvider;
import java.io.IOException;
import java.io.InputStream;
import java.security.DrbgParameters;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.HashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.crypto.Cipher;
import javax.crypto.Mac;

public final class DefaultCryptographyImpl implements Cryptography {

    public static final int STREAM_BUFFER_SIZE = 8192;
    private static final String SECURE_RANDOM_ALGORITHM = "DRBG";

    private static final ThreadLocal<HashMap<HashAlgorithm, MessageDigest>> hashAlgorithmCache = ThreadLocal
            .withInitial(HashMap::new);

    private static final ThreadLocal<HashMap<SignatureAlgorithm, Signature>> signatureAlgorithmCache = ThreadLocal
            .withInitial(HashMap::new);

    private static final ThreadLocal<HashMap<CipherTransformation, Cipher>> cipherAlgorithmCache = ThreadLocal
            .withInitial(HashMap::new);

    private static final ThreadLocal<HashMap<MacAlgorithm, Mac>> macAlgorithmCache = ThreadLocal
            .withInitial(HashMap::new);

    private static final ThreadLocal<SecureRandom> secureRandomCache =
            ThreadLocal.withInitial(DefaultCryptographyImpl::acquireRandom);

    private final ExecutorService executorService;

    /**
     *
     */
    private DefaultCryptographyImpl() {
        this.executorService = Executors.newCachedThreadPool();
    }

    public static void applyToStream(final InputStream stream,
                                     final TriConsumer<byte[], Integer, Integer> fn) throws IOException, GeneralSecurityException {
        applyToStream(stream, STREAM_BUFFER_SIZE, fn);
    }

    public static void applyToStream(final InputStream stream, final int blockSize,
                                     final TriConsumer<byte[], Integer, Integer> fn) throws IOException, GeneralSecurityException {
        final byte[] buffer = new byte[blockSize];

        int bytesRead = stream.readNBytes(buffer, 0, buffer.length);

        while (bytesRead > 0) {
            fn.apply(buffer, 0, bytesRead);
            bytesRead = stream.readNBytes(buffer, 0, buffer.length);
        }
    }

    public static Cryptography newInstance() {
        return new DefaultCryptographyImpl();
    }

    private static <T, E extends CryptoPrimitiveSupplier<T>> T acquireAlgorithm(final E algorithm,
                                                                                final ThreadLocal<HashMap<E, T>> threadLocal) {
        final HashMap<E, T> cache = threadLocal.get();

        if (!cache.containsKey(algorithm)) {
            cache.put(algorithm, algorithm.instance());
        }

        return cache.get(algorithm);
    }

    private static SecureRandom acquireRandom() {
        DrbgParameters.Instantiation params =
                DrbgParameters.instantiation(256, DrbgParameters.Capability.PR_AND_RESEED, null);

        try {
            return SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM, params);
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptographyException(ex);
        }
    }

    public ExecutorService executorService() {
        return executorService;
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
        secureRandomCache.remove();
    }

    @Override
    public DigestProvider digest() {
        return new DigestProviderImpl(this);
    }

    @Override
    public EncryptionProvider encryption() {
        return new EncryptionProviderImpl(this);
    }

    @Override
    public MacProvider mac() {
        return new MacProviderImpl(this);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Cipher primitive(final CipherTransformation algorithm) {
        return acquireAlgorithm(algorithm, cipherAlgorithmCache);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Signature primitive(final SignatureAlgorithm algorithm) {
        return acquireAlgorithm(algorithm, signatureAlgorithmCache);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public MessageDigest primitive(final HashAlgorithm algorithm) {
        return acquireAlgorithm(algorithm, hashAlgorithmCache);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Mac primitive(final MacAlgorithm algorithm) {
        return acquireAlgorithm(algorithm, macAlgorithmCache);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public SecureRandom random() {
        return secureRandomCache.get();
    }

    @Override
    public SignatureProvider signature() {
        return new SignatureProviderImpl(this);
    }
}
