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
import com.servercurio.fabric.security.spi.PrimitiveProvider;
import java.security.DrbgParameters;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.HashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.validation.constraints.NotNull;
import org.apache.commons.lang3.tuple.Pair;

import static com.servercurio.fabric.lang.Validators.throwIfArgIsNull;

public class PrimitiveProviderImpl implements PrimitiveProvider {

    /**
     * The {@code threadLocal} parameter name represented as a string value.
     */
    private static final String THREAD_LOCAL_PARAM = "threadLocal";

    /**
     * The {@code algorithm} parameter name represented as a string value.
     */
    private static final String ALGORITHM_PARAM = "algorithm";

    /**
     * The number of times a thread may acquire a cached {@link SecureRandom} instance before a reseed operation is
     * required.
     */
    private static final int RESEED_INTERVAL = 100;

    /**
     * The default {@link SecureRandom} implementation to use for all instances.
     */
    private static final String SECURE_RANDOM_ALGORITHM = "DRBG";

    /**
     * The thread local instance for the {@link HashAlgorithm} cache.
     */
    private static final ThreadLocal<HashMap<HashAlgorithm, MessageDigest>> hashAlgorithmCache = ThreadLocal
            .withInitial(
                    HashMap::new);

    /**
     * The thread local instance for the {@link SignatureAlgorithm} cache.
     */
    private static final ThreadLocal<HashMap<SignatureAlgorithm, Signature>> signatureAlgorithmCache = ThreadLocal
            .withInitial(
                    HashMap::new);

    /**
     * The thread local instance for the {@link CipherTransformation} cache.
     */
    private static final ThreadLocal<HashMap<CipherTransformation, Cipher>> cipherAlgorithmCache = ThreadLocal
            .withInitial(
                    HashMap::new);

    /**
     * The thread local instance for the {@link MacAlgorithm} cache.
     */
    private static final ThreadLocal<HashMap<MacAlgorithm, Mac>> macAlgorithmCache = ThreadLocal
            .withInitial(HashMap::new);

    /**
     * The thread local instance for the {@link SecureRandom} cache.
     */
    private static final ThreadLocal<Pair<AtomicInteger, SecureRandom>> secureRandomCache =
            ThreadLocal.withInitial(PrimitiveProviderImpl::acquireRandom);

    /**
     * The shared thread pool used by all the provider implementations.
     */
    private final ExecutorService executorService;


    /**
     * Constructs a new provider instance.
     */
    public PrimitiveProviderImpl() {
        this.executorService = Executors.newCachedThreadPool();
    }

    /**
     * Acquires an instance of the cryptographic primitive specified by the {@code algorithm} parameter and retrieved
     * from the {@code threadLocal} cache.
     *
     * @param algorithm
     *         the type of the algorithm to instantiate, not null
     * @param threadLocal
     *         the thread local cache, not null
     * @param <T>
     *         the type of the JCE algorithm primitive
     * @param <E>
     *         the type of algorithm enumeration
     * @return the primitive instance, not null
     */
    //CHECKSTYLE.OFF: IndentationCheck
    private static <T, E extends CryptoPrimitiveSupplier<T>>
    T acquireAlgorithm(@NotNull final E algorithm, @NotNull final ThreadLocal<HashMap<E, T>> threadLocal) {
        //CHECKSTYLE.ON: IndentationCheck
        throwIfArgIsNull(algorithm, ALGORITHM_PARAM);
        throwIfArgIsNull(threadLocal, THREAD_LOCAL_PARAM);

        final HashMap<E, T> cache = threadLocal.get();

        if (!cache.containsKey(algorithm)) {
            cache.put(algorithm, algorithm.instance());
        }

        return cache.get(algorithm);
    }

    /**
     * Factory method to create a new {@link SecureRandom} instance using the default algorithm specified by the {@link
     * #SECURE_RANDOM_ALGORITHM} constant.
     *
     * @return a new {@link SecureRandom} instance, not null
     */
    private static Pair<AtomicInteger, SecureRandom> acquireRandom() {
        DrbgParameters.Instantiation params =
                DrbgParameters.instantiation(256, DrbgParameters.Capability.PR_AND_RESEED, null);

        try {
            return Pair.of(new AtomicInteger(), SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM, params));
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptographyException(ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ExecutorService executorService() {
        return executorService;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void close() throws Exception {
        executorService.shutdownNow();
        hashAlgorithmCache.remove();
        macAlgorithmCache.remove();
        cipherAlgorithmCache.remove();
        signatureAlgorithmCache.remove();
        secureRandomCache.remove();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Cipher primitive(@NotNull final CipherTransformation algorithm) {
        return acquireAlgorithm(algorithm, cipherAlgorithmCache);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Signature primitive(@NotNull final SignatureAlgorithm algorithm) {
        return acquireAlgorithm(algorithm, signatureAlgorithmCache);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public MessageDigest primitive(@NotNull final HashAlgorithm algorithm) {
        return acquireAlgorithm(algorithm, hashAlgorithmCache);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Mac primitive(@NotNull final MacAlgorithm algorithm) {
        return acquireAlgorithm(algorithm, macAlgorithmCache);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public SecureRandom random() {
        final Pair<AtomicInteger, SecureRandom> randomPair = secureRandomCache.get();
        final AtomicInteger reseedCounter = randomPair.getLeft();
        final SecureRandom random = randomPair.getRight();

        final int counterValue = reseedCounter.incrementAndGet();

        if (counterValue >= RESEED_INTERVAL) {
            random.reseed(DrbgParameters.reseed(true, null));
            reseedCounter.set(0);
        }

        return random;
    }
}
