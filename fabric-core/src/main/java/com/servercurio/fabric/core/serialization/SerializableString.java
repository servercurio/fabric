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

package com.servercurio.fabric.core.serialization;

import com.servercurio.fabric.core.security.AbstractHashable;
import com.servercurio.fabric.core.security.Cryptography;
import com.servercurio.fabric.core.security.Hash;
import com.servercurio.fabric.core.security.HashAlgorithm;
import org.apache.commons.lang3.builder.CompareToBuilder;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.Collections;
import java.util.SortedSet;
import java.util.TreeSet;

public class SerializableString extends AbstractHashable implements SerializationAware, ByteConvertible, Comparable<SerializableString> {

    public static final ObjectId OBJECT_ID = new ObjectId(1, 67980);
    public static final SortedSet<Version> VERSIONS;

    private static final String EMPTY_STRING = "";

    private String value;

    static {
        final TreeSet<Version> versionSet = new TreeSet<>();
        versionSet.add(new Version(1, 0, 0));

        VERSIONS = Collections.unmodifiableSortedSet(versionSet);
    }

    public SerializableString() {
        this(EMPTY_STRING);
    }

    public SerializableString(final HashAlgorithm algorithm) {
        this(EMPTY_STRING, algorithm);
    }

    public SerializableString(final CharSequence value) {
        this(value, HashAlgorithm.SHA_384);
    }

    public SerializableString(final CharSequence value, final HashAlgorithm algorithm) {
        super(algorithm);

        if (value == null) {
            throw new IllegalArgumentException("value");
        }

        this.value = Normalizer.normalize(value, Normalizer.Form.NFC);
    }

    public String getValue() {
        return value;
    }

    @Override
    public byte[] toBytes() {
        return (value != null && !value.isEmpty()) ? value.getBytes(StandardCharsets.UTF_8) : new byte[0];
    }

    @Override
    public void fromBytes(final byte[] bytes) {
        value = new String(bytes, StandardCharsets.UTF_8);
    }

    @Override
    protected Hash computeHash(final HashAlgorithm algorithm, final Cryptography cryptography) {
        return cryptography.digestSync(algorithm, toBytes());
    }

    @Override
    public ObjectId getObjectId() {
        return OBJECT_ID;
    }

    @Override
    public SortedSet<Version> getVersionHistory() {
        return VERSIONS;
    }

    @Override
    public Version getVersion() {
        return VERSIONS.last();
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }

        if (o == null || (getClass() != o.getClass() && !o.getClass().isAssignableFrom(getClass()))) {
            return false;
        }

        final SerializableString that = (SerializableString) o;

        return new EqualsBuilder()
                .append(value, that.value)
                .isEquals();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37)
                .append(value)
                .toHashCode();
    }

    @Override
    public String toString() {
        return value;
    }

    @Override
    public int compareTo(final SerializableString that) {
        if (this == that) {
            return 0;
        }

        if (that == null) {
            return -1;
        }

        return new CompareToBuilder().append(this.value, that.value).build();
    }
}
