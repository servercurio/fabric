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
import java.security.Security;
import java.security.Signature;
import java.util.HashMap;
import java.util.ServiceLoader;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Positive;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import static com.servercurio.fabric.lang.Validators.throwIfArgIsNotPositive;
import static com.servercurio.fabric.lang.Validators.throwIfArgIsNull;

/**
 * Default {@link Cryptography} implementation provided by the base {@code Fabric} library.
 *
 * @author Nathan Klick
 * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html">Java
 *         Cryptography Architecture</a>
 */
public class DefaultCryptographyImpl implements Cryptography {

    /**
     * The default buffer size to use when reading/writing blocks of data from streams.
     */
    public static final int STREAM_BUFFER_SIZE = 8192;

    /**
     * The {@code stream} parameter name represented as a string value.
     */
    private static final String STREAM_PARAM = "stream";

    /**
     * The {@code fn} parameter name represented as a string value.
     */
    private static final String FN_PARAM = "fn";

    /**
     * The {@code blockSize} parameter name represented as a string value.
     */
    private static final String BLOCK_SIZE_PARAM = "blockSize";

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
            ThreadLocal.withInitial(DefaultCryptographyImpl::acquireRandom);

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * The shared thread pool used by all the provider implementations.
     */
    private final ExecutorService executorService;

    /**
     * Private default constructor.
     */
    protected DefaultCryptographyImpl() {
        this.executorService = Executors.newCachedThreadPool();
    }

    /**
     * Utility method that applies reads {@link #STREAM_BUFFER_SIZE} blocks from the {@code stream} parameter and
     * applies the {@code fn} lambda function to each block. This method will read from the stream until it reaches the
     * end of the stream.
     *
     * @param stream
     *         the input stream from which blocks are read, not null
     * @param fn
     *         the lambda function to be applied to each block, not null
     * @throws IOException
     *         if an error occurs while reading from the input stream
     * @throws GeneralSecurityException
     *         if an errors occurs while performing a cryptographic operation
     * @throws IllegalArgumentException
     *         if the {@code stream} or the {@code fn} parameters are null
     */
    public static void applyToStream(@NotNull final InputStream stream,
                                     @NotNull final TriConsumer<byte[], Integer, Integer> fn) throws
                                                                                              IOException,
                                                                                              GeneralSecurityException {
        applyToStream(stream, STREAM_BUFFER_SIZE, fn);
    }

    /**
     * Utility method that applies reads {@code blockSize} blocks from the {@code stream} parameter and applies the
     * {@code fn} lambda function to each block. This method will read from the stream until it reaches the end of the
     * stream.
     *
     * @param stream
     *         the input stream from which blocks are read, not null
     * @param blockSize
     *         the maximum size of each block to read, positive integer
     * @param fn
     *         the lambda function to be applied to each block, not null
     * @throws IOException
     *         if an error occurs while reading from the input stream
     * @throws GeneralSecurityException
     *         if an errors occurs while performing a cryptographic operation
     * @throws IllegalArgumentException
     *         if the {@code stream} or {@code fn} parameters are null or if the {@code blockSize} paramter is less than
     *         or equal to zero
     */
    public static void applyToStream(@NotNull final InputStream stream, @Positive final int blockSize,
                                     @NotNull final TriConsumer<byte[], Integer, Integer> fn) throws
                                                                                              IOException,
                                                                                              GeneralSecurityException {
        throwIfArgIsNull(stream, STREAM_PARAM);
        throwIfArgIsNotPositive(blockSize, BLOCK_SIZE_PARAM);
        throwIfArgIsNull(fn, FN_PARAM);

        final byte[] buffer = new byte[blockSize];

        int bytesRead = stream.readNBytes(buffer, 0, buffer.length);

        while (bytesRead > 0) {
            fn.apply(buffer, 0, bytesRead);
            bytesRead = stream.readNBytes(buffer, 0, buffer.length);
        }
    }

    /**
     * Factory method that creates a new instance on every invocation.
     *
     * @return a new {@linkplain Cryptography} instance, not null
     */
    public static Cryptography newInstance() {
        return new DefaultCryptographyImpl();
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
     * Gets the configured {@link ExecutorService} for this {@linkplain Cryptography} instance.
     *
     * @return the executor service, not null
     */
    public ExecutorService executorService() {
        return executorService;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public DigestProvider digest() {
        return ServiceLoader.load(DigestProvider.class)
                            .findFirst()
                            .orElseGet(() -> new DigestProviderImpl(this));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public EncryptionProvider encryption() {
        return ServiceLoader.load(EncryptionProvider.class)
                            .findFirst()
                            .orElseGet(() -> new EncryptionProviderImpl(this));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public MacProvider mac() {
        return ServiceLoader.load(MacProvider.class)
                            .findFirst()
                            .orElseGet(() -> new MacProviderImpl(this));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public SignatureProvider signature() {
        return ServiceLoader.load(SignatureProvider.class)
                            .findFirst()
                            .orElseGet(() -> new SignatureProviderImpl(this));
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
