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

import com.servercurio.fabric.lang.ComparableConstants;
import java.util.Arrays;
import java.util.Base64;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Positive;
import org.apache.commons.lang3.builder.CompareToBuilder;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

/**
 * Represents a mutable cryptographic hash value that includes the algorithm used to perform the original computation.
 * Acts as a basic wrapper class to simplify basic operations such as making copies, generating string representations,
 * and comparing for equality. An {@link ImmutableHash} variant is provided as a subclass for convenience.
 *
 * @author Nathan Klick
 * @see HashAlgorithm
 * @see ImmutableHash
 */
public class Hash implements Comparable<Hash> {

    /**
     * Constant value representing an empty hash using a zero-length byte array and {@link HashAlgorithm#NONE} as the
     * algorithm.
     *
     * @see #Hash()
     */
    public static final Hash EMPTY = new Hash().immutable();

    /**
     * The {@code algorithm} field name represented as a string value.
     */
    private static final String ALGORITHM_FIELD = "algorithm";

    /**
     * The {@code value} field name represented as a string value.
     */
    private static final String VALUE_FIELD = "value";

    /**
     * The {@code other} parameter name represented as a string value.
     */
    private static final String OTHER_PARAM = "other";

    /**
     * The default length of the hex prefix returned by the {@link #toPrefix()} method.
     *
     * @see #toPrefix()
     * @see #toPrefix(int)
     */
    private static final int DEFAULT_PREFIX_LEN = 4;


    /**
     * The hash algorithm used to compute the hash value.
     *
     * @see HashAlgorithm
     * @see #getAlgorithm()
     * @see #setAlgorithm(HashAlgorithm)
     */
    @NotNull
    private HashAlgorithm algorithm;

    /**
     * The underlying byte array containing the hash value.
     *
     * @see #getValue()
     * @see #setValue(byte[])
     */
    @NotNull
    private byte[] value;

    /**
     * Constructs an empty {@link Hash} instance using a zero-length byte array and {@link HashAlgorithm#NONE} as the
     * algorithm. This is equivalent to the provided {@link #EMPTY} constant.
     *
     * @see HashAlgorithm#NONE
     * @see Hash#EMPTY
     */
    public Hash() {
        this(HashAlgorithm.NONE, new byte[0], false);
    }

    /**
     * Constructs a new {@link Hash} instance using the provided {@link HashAlgorithm} and computed hash value. This
     * constructor does not copy the provided hash value and instead uses the {@code value} parameter as the underlying
     * byte array. Care must be taken to not reuse the byte array supplied to the {@code value} parameter.
     *
     * @param algorithm
     *         the hash algorithm used to compute the hash value, not null
     * @param value
     *         the byte array representing the computed hash value, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm} is null or the {@code value} parameter is null or the length of the byte array
     *         does not equal the {@link HashAlgorithm#bytes()} length
     */
    public Hash(@NotNull final HashAlgorithm algorithm, @NotNull final byte[] value) {
        this(algorithm, value, false);
    }

    /**
     * Constructs a new {@link Hash} instance using the provided {@link HashAlgorithm} and computed hash value. If the
     * {@code copyValue} parameter is {@code true} then the supplied byte array is copied using the {@link
     * Arrays#copyOf(byte[], int)} method.
     *
     * @param algorithm
     *         the hash algorithm used to compute the hash value, not null
     * @param value
     *         the byte array representing the computed hash value, not null
     * @param copyValue
     *         if {@code true} the {@code value} parameter is copied; otherwise the {@code value} parameter is used as
     *         the underlying byte array
     * @throws IllegalArgumentException
     *         if the {@code algorithm} is null or the {@code value} parameter is null or the length of the byte array
     *         does not equal the {@link HashAlgorithm#bytes()} length
     */
    public Hash(@NotNull final HashAlgorithm algorithm, @NotNull final byte[] value, final boolean copyValue) {
        if (algorithm == null) {
            throw new IllegalArgumentException(ALGORITHM_FIELD);
        }

        if (value == null || (algorithm != HashAlgorithm.NONE && value.length != algorithm.bytes())) {
            throw new IllegalArgumentException(VALUE_FIELD);
        }

        this.algorithm = algorithm;
        this.value = (copyValue) ? Arrays.copyOf(value, value.length) : value;
    }

    /**
     * Copy Constructor. The underlying byte array is copied using the {@link Arrays#copyOf(byte[], int)} method.
     *
     * @param other
     *         the {@link Hash} instance to copy, not null
     * @throws IllegalArgumentException
     *         if the {@code other} parameter is null
     */
    public Hash(@NotNull final Hash other) {
        if (other == null) {
            throw new IllegalArgumentException(OTHER_PARAM);
        }

        this.algorithm = other.getAlgorithm();

        if (other.value != null) {
            this.value = Arrays.copyOf(other.value, other.value.length);
        }
    }


    /**
     * Returns the algorithm that computed the underlying hash value, as specified by the {@link HashAlgorithm} enum.
     *
     * @return the hash algorithm used to compute the hash value, not null
     * @see HashAlgorithm
     */
    public HashAlgorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * Changes the algorithm type and allocates a new underlying zero-filled byte array of the appropriate length. Any
     * previous hash value represented by this instance will be discarded.
     *
     * @param algorithm
     *         the hash algorithm used to compute the hash value, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm} parameter is null
     * @see HashAlgorithm
     */
    public void setAlgorithm(@NotNull final HashAlgorithm algorithm) {
        if (algorithm == null) {
            throw new IllegalArgumentException(ALGORITHM_FIELD);
        }

        this.algorithm = algorithm;
        this.value = new byte[algorithm.bytes()];
    }

    /**
     * Returns the underlying byte array containing the hash value. This method allows for direct modification of the
     * underlying pre-allocated buffer of the length specified by configured algorithm type.
     *
     * @return the underlying byte array representing the computed hash value, not null
     * @see HashAlgorithm
     * @see Hash#getAlgorithm()
     */
    public byte[] getValue() {
        return value;
    }

    /**
     * Replaces the underlying byte array containing the hash value. This method will validate the length of the
     * provided byte array and will throw an {@link IllegalArgumentException} if the length does not match the hash size
     * of the specified algorithm. This method does not make a copy of the provided byte array and therefore care must
     * be taken to avoid reusing the byte array supplied to this method.
     *
     * @param value
     *         the new underlying byte array representing the computed hash value, not null
     * @throws IllegalArgumentException
     *         if the {@code value} parameter is null or the length is not equal to the {@link HashAlgorithm#bytes()}
     *         length
     * @see HashAlgorithm
     * @see #getAlgorithm()
     * @see #getValue()
     */
    public void setValue(@NotNull final byte[] value) {
        if (value == null || value.length != getAlgorithm().bytes()) {
            throw new IllegalArgumentException(VALUE_FIELD);
        }

        this.value = value;
    }

    /**
     * Returns true if the underlying byte array contains all zeros or if the algorithm type is {@link
     * HashAlgorithm#NONE}.
     *
     * @return true if the underlying byte array contains all zeros; otherwise false
     * @see HashAlgorithm
     */
    public boolean isEmpty() {
        if (getAlgorithm() == HashAlgorithm.NONE) {
            return true;
        }

        for (final byte b : value) {
            if (b != 0) {
                return false;
            }
        }

        return true;
    }

    /**
     * Converts this mutable {@link Hash} instance to an {@link ImmutableHash} instance. If {@code this} instance is
     * already an {@link ImmutableHash} then the method will return the current instance without creating an additional
     * copy.
     *
     * @return an instance of {@link ImmutableHash} or {@code this} if the current instance is already an {@link
     *         ImmutableHash}
     * @see ImmutableHash
     */
    public Hash immutable() {
        if (this.getClass() == ImmutableHash.class) {
            return this;
        }

        return new ImmutableHash(this);
    }

    /**
     * Returns the first {@code count} bytes represented as a hexadecimal string. The {@code count} parameter must be
     * greater than zero and less than the total size of the hash in bytes.
     *
     * @param count
     *         the number of bytes to include in the prefix, positive and greater than zero
     * @return the hexadecimal string representation of the first {@code count} bytes
     * @throws IndexOutOfBoundsException
     *         if the {@code count} parameter is less than zero, equals zero, or is greater than the length of the
     *         underlying byte array
     * @see HashAlgorithm
     */
    public String toPrefix(@Positive final int count) {
        if (count <= 0 || count > value.length) {
            throw new IndexOutOfBoundsException(count);
        }

        final StringBuilder sb = new StringBuilder();

        for (int i = 0; i < count; i++) {
            sb.append(String.format("%02x", value[i]));
        }

        return sb.toString();
    }

    /**
     * Returns the first four (4) bytes represented as a hexadecimal string. Uses the {@link #toPrefix(int)}
     * implementation.
     *
     * @return the hexadecimal string representation of the first four (4) bytes
     * @throws IndexOutOfBoundsException
     *         if the total length of the hash is less than four (4) bytes, such as a hash of type {@link
     *         HashAlgorithm#NONE}
     * @see #toPrefix(int)
     */
    public String toPrefix() {
        return toPrefix(DEFAULT_PREFIX_LEN);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int compareTo(@NotNull final Hash other) {
        if (this == other) {
            return ComparableConstants.EQUAL;
        }

        if (other == null) {
            return ComparableConstants.GREATER_THAN;
        }

        return new CompareToBuilder()
                .append(this.getAlgorithm(), other.getAlgorithm())
                .append(this.value, other.value)
                .build();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37)
                .append(getAlgorithm())
                .append(value)
                .toHashCode();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }

        if (o == null || (getClass() != o.getClass() && !o.getClass().isAssignableFrom(getClass()))) {
            return false;
        }

        final Hash hash = (Hash) o;

        return new EqualsBuilder()
                .append(getAlgorithm(), hash.getAlgorithm())
                .append(value, hash.value)
                .isEquals();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.JSON_STYLE)
                .append(ALGORITHM_FIELD, algorithm)
                .append(VALUE_FIELD, Base64.getEncoder().encodeToString(value))
                .build();
    }
}