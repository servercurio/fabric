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
import org.apache.commons.lang3.builder.CompareToBuilder;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

/**
 * Represents a immutable cryptographic signature that includes the algorithm used to perform the original computation.
 * Acts as a basic wrapper class to simplify basic operations such as making copies, generating string representations,
 * and comparing for equality. 
 *
 * @author Nathan Klick
 * @see SignatureAlgorithm
 * @since 1.0
 */
public class Seal implements Comparable<Seal> {

    /**
     * Constant value representing an empty signature using a zero-length byte array and {@link SignatureAlgorithm#NONE}
     * as the algorithm.
     *
     * @see #Seal()
     */
    public static final Seal EMPTY = new Seal();

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
     * The algorithm used to compute the signature.
     *
     * @see SignatureAlgorithm
     * @see #getAlgorithm()
     */
    @NotNull
    private final SignatureAlgorithm algorithm;

    /**
     * The underlying byte array containing the signature.
     *
     * @see #getValue()
     */
    @NotNull
    private final byte[] value;

    /**
     * Constructs an empty {@link Seal} instance using a zero-length byte array and {@link SignatureAlgorithm#NONE} as
     * the algorithm. This is equivalent to the provided {@link #EMPTY} constant.
     *
     * @see SignatureAlgorithm#NONE
     * @see Seal#EMPTY
     */
    private Seal() {
        this(SignatureAlgorithm.NONE, new byte[0], false);
    }

    /**
     * Constructs a new {@link Seal} instance using the provided {@link SignatureAlgorithm} and signature. This
     * constructor copies the provided signature to ensure immutability is preserved.
     *
     * @param algorithm
     *         the hash algorithm used to compute the signature, not null
     * @param value
     *         the byte array representing the computed signature, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm} is null or the {@code value} parameter is null or the length of the byte array
     *         is zero
     */
    public Seal(@NotNull final SignatureAlgorithm algorithm, @NotNull final byte[] value) {
        this(algorithm, value, true);
    }

    /**
     * Copy Constructor. The underlying byte array is copied using the {@link Arrays#copyOf(byte[], int)} method.
     *
     * @param other
     *         the {@link Seal} instance to copy, not null
     * @throws IllegalArgumentException
     *         if the {@code other} parameter is null
     */
    public Seal(@NotNull final Seal other) {
        if (other == null) {
            throw new IllegalArgumentException(OTHER_PARAM);
        }

        this.algorithm = other.algorithm;
        this.value = Arrays.copyOf(other.value, other.value.length);
    }

    /**
     * Constructs a new {@link Seal} instance using the provided {@link SignatureAlgorithm} and signature. If the {@code
     * copyValue} parameter is {@code true} then the supplied byte array is copied using the {@link
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
     *         is zero
     */
    protected Seal(@NotNull final SignatureAlgorithm algorithm, @NotNull final byte[] value, final boolean copyValue) {

        if (algorithm == null) {
            throw new IllegalArgumentException(ALGORITHM_FIELD);
        }

        if (value == null || (algorithm != SignatureAlgorithm.NONE && value.length == 0)) {
            throw new IllegalArgumentException(VALUE_FIELD);
        }

        this.algorithm = algorithm;
        this.value = (copyValue) ? Arrays.copyOf(value, value.length) : value;
    }

    /**
     * Returns the algorithm that computed the underlying signature, as specified by the {@link SignatureAlgorithm} enum.
     *
     * @return the signature algorithm used to compute the signature, not null
     * @see SignatureAlgorithm
     */
    public SignatureAlgorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * Returns a copy of the underlying byte array containing the signature.
     *
     * @return a copy of the underlying byte array representing the computed signature, not null
     * @see SignatureAlgorithm
     * @see #getAlgorithm()
     */
    public byte[] getValue() {
        return Arrays.copyOf(value, value.length);
    }

    /**
     * Returns true if the underlying byte array contains all zeros or if the algorithm type is {@link
     * SignatureAlgorithm#NONE}.
     *
     * @return true if the underlying byte array contains all zeros; otherwise false
     */
    public boolean isEmpty() {
        if (getAlgorithm() == SignatureAlgorithm.NONE) {
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
     * {@inheritDoc}
     */
    @Override
    public int compareTo(@NotNull final Seal that) {
        if (this == that) {
            return ComparableConstants.EQUAL;
        }

        if (that == null) {
            return ComparableConstants.GREATER_THAN;
        }

        return new CompareToBuilder()
                .append(algorithm, that.algorithm)
                .append(value, that.value)
                .build();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37)
                .append(algorithm)
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

        final Seal seal = (Seal) o;

        return new EqualsBuilder()
                .append(algorithm, seal.algorithm)
                .append(value, seal.value)
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
                .toString();
    }
}
