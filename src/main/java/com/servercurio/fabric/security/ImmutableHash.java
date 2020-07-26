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

import java.util.Arrays;
import javax.validation.constraints.NotNull;

/**
 * Represents an immutable cryptographic hash value that includes the algorithm used to perform the original
 * computation. Acts as a basic wrapper class to simplify basic operations such as making copies, generating string
 * representations, and comparing for equality.
 *
 * @author Nathan Klick
 * @see HashAlgorithm
 * @see Hash
 * @since 1.0
 */
public class ImmutableHash extends Hash {

    /**
     * Constructs a new {@link ImmutableHash} instance using the provided {@link HashAlgorithm} and computed hash value.
     * This constructor copies the {@code value} parameter to ensure immutability.
     *
     * @param algorithm
     *         the hash algorithm used to compute the hash value, not null
     * @param value
     *         the byte array representing the computed hash value, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm} is null or the {@code value} parameter is null or the length of the byte array
     *         does not equal the {@link HashAlgorithm#bytes()} length
     */
    public ImmutableHash(@NotNull final HashAlgorithm algorithm, @NotNull final byte[] value) {
        super(algorithm, value, true);
    }

    /**
     * Copy Constructor. The underlying byte array is copied using the {@link Arrays#copyOf(byte[], int)} method.
     *
     * @param other
     *         the {@link Hash} instance to copy, not null
     * @throws IllegalArgumentException
     *         if the {@code other} parameter is null
     */
    public ImmutableHash(final Hash other) {
        super(other);
    }

    /**
     * {@inheritDoc}
     *
     * @param algorithm
     *         {@inheritDoc}
     * @throws UnsupportedOperationException
     *         always because this method is not supported on immutable instances
     */
    @Override
    public void setAlgorithm(final HashAlgorithm algorithm) {
        throw new UnsupportedOperationException();
    }

    /**
     * Returns a copy of the underlying byte array containing the hash value.
     *
     * @return a copy of the underlying byte array, not null
     * @see HashAlgorithm
     * @see Hash#getAlgorithm()
     */
    @Override
    public byte[] getValue() {
        final byte[] value = super.getValue();

        return Arrays.copyOf(value, value.length);
    }

    /**
     * {@inheritDoc}
     *
     * @param value
     *         {@inheritDoc}
     * @throws UnsupportedOperationException
     *         always because this method is not supported on immutable instances
     */
    @Override
    public void setValue(final byte[] value) {
        throw new UnsupportedOperationException();
    }

    /**
     * Converts this {@link ImmutableHash} instance to a mutable {@link Hash} instance.
     *
     * @return an instance of {@link Hash}
     * @see Hash
     */
    public Hash mutable() {
        return new Hash(this);
    }
}
