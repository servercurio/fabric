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
import org.apache.commons.lang3.builder.CompareToBuilder;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

public class Seal implements Comparable<Seal> {

    //region Public Constants
    public static final Seal EMPTY = new Seal();
    //endregion

    //region Private Constants
    private static final String ALGORITHM_FIELD = "algorithm";
    private static final String VALUE_FIELD = "value";
    private static final String OTHER_PARAM = "other";

    //endregion

    private SignatureAlgorithm algorithm;

    private byte[] value;

    private Seal() {
        this(SignatureAlgorithm.NONE, new byte[0], false);
    }

    public Seal(final SignatureAlgorithm algorithm, final byte[] value) {
        this(algorithm, value, true);
    }

    public Seal(final Seal other) {
        if (other == null) {
            throw new IllegalArgumentException(OTHER_PARAM);
        }

        this.algorithm = other.algorithm;
        this.value = Arrays.copyOf(other.value, other.value.length);
    }

    protected Seal(final SignatureAlgorithm algorithm, final byte[] value, final boolean copyValue) {

        if (algorithm == null) {
            throw new IllegalArgumentException(ALGORITHM_FIELD);
        }

        if (value == null || (algorithm != SignatureAlgorithm.NONE && value.length == 0)) {
            throw new IllegalArgumentException(VALUE_FIELD);
        }

        this.algorithm = algorithm;
        this.value = (copyValue) ? Arrays.copyOf(value, value.length) : value;
    }

    public SignatureAlgorithm getAlgorithm() {
        return algorithm;
    }

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
    public int compareTo(final Seal that) {
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

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.JSON_STYLE)
                .append(ALGORITHM_FIELD, algorithm)
                .append(VALUE_FIELD, Base64.getEncoder().encodeToString(value))
                .toString();
    }
}
