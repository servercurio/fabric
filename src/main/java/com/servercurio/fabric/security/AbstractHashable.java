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

package com.servercurio.fabric.security;

import javax.validation.constraints.NotNull;

import static com.servercurio.fabric.lang.Validators.throwIfArgIsNull;

/**
 * Provides a reasonable default {@link Hashable} implementation for classes that should compute their own cryptographic
 * {@link Hash} value.
 *
 * @author Nathan Klick
 * @see Hashable
 * @see Hash
 */
public abstract class AbstractHashable implements Hashable {

    /**
     * The {@code algorithm} field name represented as a string value.
     */
    private static final String ALGORITHM_FIELD = "algorithm";

    /**
     * The {@code cryptography} field name represented as a string value.
     */
    private static final String CRYPTOGRAPHY_FIELD = "cryptography";

    /**
     * The {@link HashAlgorithm} to be used when computing the hash value.
     */
    @NotNull
    private final HashAlgorithm algorithm;

    /**
     * The {@link Cryptography} instance to be used when computing the hash value.
     */
    @NotNull
    private final Cryptography cryptography;

    /**
     * The computed hash value or {@code null} if no hash has been computed.
     */
    private Hash hash;

    /**
     * Standard no-argument constructor which defaults to using {@link HashAlgorithm#SHA_384} as the hash algorithm.
     */
    public AbstractHashable() {
        this(HashAlgorithm.SHA_384);
    }

    /**
     * Constructor that uses the provided {@link HashAlgorithm} and uses {@link Cryptography#newDefaultInstance()} as
     * the default cryptography instance.
     *
     * @param algorithm
     *         the algorithm to use when computing the hash value, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm} parameter is null
     */
    public AbstractHashable(@NotNull final HashAlgorithm algorithm) {
        this(algorithm, Cryptography.newDefaultInstance());
    }

    /**
     * Constructor that uses the provided {@link HashAlgorithm} and {@link Cryptography} instances.
     *
     * @param algorithm
     *         the algorithm to use when computing the hash value, not null
     * @param cryptography
     *         the cryptography instance to use when computing the hash value, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm} or {@code cryptography} parameters are null
     */
    public AbstractHashable(@NotNull final HashAlgorithm algorithm, @NotNull final Cryptography cryptography) {
        throwIfArgIsNull(algorithm, ALGORITHM_FIELD);
        throwIfArgIsNull(cryptography, CRYPTOGRAPHY_FIELD);

        this.algorithm = algorithm;
        this.cryptography = cryptography;
    }

    /**
     * Gets the algorithm used to compute the hash value.
     *
     * @return the cryptographic hash algorithm, not null
     */
    public HashAlgorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * Gets the cryptography instance used to compute the hash value.
     *
     * @return the cryptography instance, not null
     */
    public Cryptography getCryptography() {
        return cryptography;
    }

    /**
     * Called by the {@link #getHash()} method to compute the hash value. The {@link #getHash()} method will only call
     * this method if no hash is currently available.
     *
     * @param algorithm
     *         the algorithm to use when computing the hash value, not null
     * @param cryptography
     *         the cryptography instance to use when computing the hash value, not null
     * @return the computed hash value, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm} or {@code cryptography} parameters are {@code null}
     */
    protected abstract Hash computeHash(@NotNull final HashAlgorithm algorithm,
                                        @NotNull final Cryptography cryptography);

    /**
     * {@inheritDoc}
     */
    @Override
    public Hash getHash() {
        if (hasHash()) {
            return hash;
        }

        setHash(computeHash(algorithm, cryptography));
        return hash;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setHash(final Hash hash) {
        if (this.hash == hash) {
            return;
        }

        this.hash = hash;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean hasHash() {
        return hash != null && !Hash.EMPTY.equals(hash);
    }
}
