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

import org.apache.commons.lang3.builder.*;

import java.util.Arrays;
import java.util.Base64;

public class Hash implements Comparable<Hash> {


    public static final Hash EMPTY = new Hash();

    private static final String ALGORITHM_FIELD = "algorithm";
    private static final String VALUE_FIELD = "value";
    private static final String OTHER_PARAM = "other";

    private static final int DEFAULT_PREFIX_LEN = 4;


    private HashAlgorithm algorithm;

    private byte[] value;

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

    public HashAlgorithm getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(final HashAlgorithm algorithm) {
        if (algorithm == null) {
            throw new IllegalArgumentException(ALGORITHM_FIELD);
        }

        this.algorithm = algorithm;
        this.value = new byte[algorithm.bytes()];
    }

    public byte[] getValue() {
        return value;
    }

    public void setValue(final byte[] value) {
        if (value == null || value.length != getAlgorithm().bytes()) {
            throw new IllegalArgumentException(VALUE_FIELD);
        }

        this.value = value;
    }

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

    public String getPrefix() {
        return getPrefix(DEFAULT_PREFIX_LEN);
    }

    public String getPrefix(final int count) {
        if (count <= 0 || count > value.length) {
            throw new IndexOutOfBoundsException(count);
        }

        final StringBuilder sb = new StringBuilder();

        for (int i = 0; i < count; i++) {
            sb.append(String.format("%02x", value[i]));
        }

        return sb.toString();
    }

    @Override
    public int compareTo(final Hash other) {
        if (other == null) {
            return 1;
        }

        return new CompareToBuilder()
                .append(this.getAlgorithm(), other.getAlgorithm())
                .append(this.value, other.value)
                .build();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37)
                .append(getAlgorithm())
                .append(value)
                .toHashCode();
    }

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


    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.JSON_STYLE)
                .append(ALGORITHM_FIELD, algorithm)
                .append(VALUE_FIELD, Base64.getEncoder().encodeToString(value))
                .build();
    }

}