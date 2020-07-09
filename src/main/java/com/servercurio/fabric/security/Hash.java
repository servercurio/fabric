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
import java.util.Base64;
import org.apache.commons.lang3.builder.CompareToBuilder;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

/**
 * @author Nathan Klick
 * @see java.lang.Comparable
 * @since 1.0
 */
public class Hash implements Comparable<Hash> {

    //region Public Constants
    public static final Hash EMPTY = new Hash().immutable();
    //endregion

    //region Private Constants
    private static final String ALGORITHM_FIELD = "algorithm";
    private static final String VALUE_FIELD = "value";
    private static final String OTHER_PARAM = "other";

    private static final int DEFAULT_PREFIX_LEN = 4;
    //endregion

    //region Private Instance Variables
    /**
     *
     */
    private HashAlgorithm algorithm;

    /**
     *
     */
    private byte[] value;
    //endregion

    //region Constructors
    public Hash() {
        this(HashAlgorithm.NONE, new byte[1], false);
    }

    public Hash(final HashAlgorithm algorithm, final byte[] value) {
        this(algorithm, value, false);
    }

    public Hash(final HashAlgorithm algorithm, final byte[] value, final boolean copyValue) {
        if (algorithm == null) {
            throw new IllegalArgumentException(ALGORITHM_FIELD);
        }

        if (value == null || (algorithm != HashAlgorithm.NONE && value.length != algorithm.bytes())) {
            throw new IllegalArgumentException(VALUE_FIELD);
        }

        this.algorithm = algorithm;
        this.value = (copyValue) ? Arrays.copyOf(value, value.length) : value;
    }

    public Hash(final Hash other) {
        if (other == null) {
            throw new IllegalArgumentException(OTHER_PARAM);
        }

        this.algorithm = other.getAlgorithm();

        if (other.value != null) {
            this.value = Arrays.copyOf(other.value, other.value.length);
        }
    }
    //endregion

    //region Getters & Setters

    /**
     * Returns the algorithm that created the underlying hash value, as specified by the {@code HashAlgorithm} enum.
     *
     * @return the type of algorithm, not null
     */
    public HashAlgorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * Changes the algorithm type and allocates a new underlying zero-filled byte array of the appropriate length. Any
     * previous value represented by this instance will be discarded.
     *
     * @param algorithm
     *         the type of the algorithm
     * @throws IllegalArgumentException
     *         if the {@code algorithm} parameter is null
     */
    public void setAlgorithm(final HashAlgorithm algorithm) {
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
     * @return the underlying byte array, not null
     * @see HashAlgorithm
     * @see Hash#getAlgorithm()
     */
    public byte[] getValue() {
        return value;
    }

    /**
     * @param value
     */
    public void setValue(final byte[] value) {
        if (value == null || value.length != getAlgorithm().bytes()) {
            throw new IllegalArgumentException(VALUE_FIELD);
        }

        this.value = value;
    }

    /**
     * Returns true if the underlying byte array contains all zeros or if the algorithm type is {@link
     * HashAlgorithm#NONE}.
     *
     * @return true if the underlying byte array contains all zero; otherwise false
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
    //endregion

    //region Member Methods

    /**
     * Returns the first four (4) bytes represented as a hexadecimal string.
     *
     * @return the hexadecimal string representation of the first four (4) bytes
     * @throws IndexOutOfBoundsException
     *         if the total length of the hash is less than four (4) bytes, such as a hash of type {@link
     *         HashAlgorithm#NONE}
     */
    public String toPrefix() {
        return toPrefix(DEFAULT_PREFIX_LEN);
    }

    /**
     * Returns the first {@code count} bytes represented as a hexadecimal string. The {@code count} parameter must be
     * greater than zero and less than the total size of the hash in bytes.
     *
     * @param count
     *         the number of bytes to include in the prefix
     * @return the hexadecimal string representation of the first {@code count} bytes
     * @throws IndexOutOfBoundsException
     *         if the {@code count} parameter is less than zero, equals zero, or is greater than the length of the
     *         underlying byte array
     */
    public String toPrefix(final int count) {
        if (count <= 0 || count > value.length) {
            throw new IndexOutOfBoundsException(count);
        }

        final StringBuilder sb = new StringBuilder();

        for (int i = 0; i < count; i++) {
            sb.append(String.format("%02x", value[i]));
        }

        return sb.toString();
    }

    public Hash immutable() {
        return new ImmutableHash(this);
    }
    //endregion

    //region ToString, Equals, HashCode, & CompareTo

    /**
     * {@inheritDoc}
     */
    @Override
    public int compareTo(final Hash other) {
        if (this == other) {
            return 0;
        }

        if (other == null) {
            return 1;
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
    //endregion

}