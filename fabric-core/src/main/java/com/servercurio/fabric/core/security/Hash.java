/*
 * Copyright 2019 Server Curio
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

package com.servercurio.fabric.core.security;

import com.servercurio.fabric.core.serialization.ObjectId;
import com.servercurio.fabric.core.serialization.SerializationAware;
import com.servercurio.fabric.core.serialization.Version;
import org.apache.commons.lang3.builder.CompareToBuilder;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import java.util.Arrays;
import java.util.Collections;
import java.util.SortedSet;
import java.util.TreeSet;

public final class Hash implements SerializationAware, Comparable<Hash> {

    public static final ObjectId OBJECT_ID = new ObjectId(1L, 27186L);
    public static SortedSet<Version> VERSIONS;

    static {
        final TreeSet<Version> versionSet = new TreeSet<>();
        versionSet.add(new Version(1, 0, 0, 0));

        VERSIONS = Collections.unmodifiableSortedSet(versionSet);
    }


    private HashAlgorithm algorithm;
    private byte[] value;

    public Hash() {
        this(HashAlgorithm.NONE, new byte[0], false);
    }

    public Hash(final HashAlgorithm algorithm, final byte[] value) {
        this(algorithm, value, false);
    }

    public Hash(final HashAlgorithm algorithm, final byte[] value, final boolean copyValue) {
        if (algorithm == null) {
            throw new IllegalArgumentException("algorithm");
        }

        if (value == null || value.length != algorithm.bytes()) {
            throw new IllegalArgumentException("value");
        }

        this.algorithm = algorithm;
        this.value = (copyValue) ? Arrays.copyOf(value, value.length) : value;
    }

    public Hash(final Hash other) {
        this.algorithm = other.algorithm;
        this.value = Arrays.copyOf(other.value, other.value.length);
    }

    public HashAlgorithm getAlgorithm() {
        return algorithm;
    }

    private void setAlgorithm(final HashAlgorithm algorithm) {
        this.algorithm = algorithm;
        this.value = new byte[algorithm.bytes()];
    }

    public byte[] getValue() {
        return value;
    }

    private void setValue(final byte[] value) {
        if (value == null || value.length != algorithm.bytes()) {
            throw new IllegalArgumentException("value");
        }

        this.value = value;
    }

    public boolean isEmpty() {
        if (HashAlgorithm.NONE.equals(algorithm)) {
            return true;
        }

        if (value == null) {
            return true;
        }

        for (final byte b : value) {
            if (b != 0) {
                return false;
            }
        }

        return true;
    }

    @Override
    public ObjectId getObjectId() {
        return OBJECT_ID;
    }

    @Override
    public SortedSet<Version> getObjectVersions() {
        return VERSIONS;
    }

    @Override
    public Version getObjectVersion() {
        return VERSIONS.last();
    }

    @Override
    public int compareTo(final Hash other) {
        if (other == null) {
            return 1;
        }

        return new CompareToBuilder()
                .append(this.algorithm, other.algorithm)
                .append(this.value, other.value)
                .build();
    }


    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37)
                .append(algorithm)
                .append(value)
                .toHashCode();
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;

        if (!(o instanceof Hash)) return false;

        final Hash hash = (Hash) o;

        return new EqualsBuilder()
                .append(algorithm, hash.algorithm)
                .append(value, hash.value)
                .isEquals();
    }
}