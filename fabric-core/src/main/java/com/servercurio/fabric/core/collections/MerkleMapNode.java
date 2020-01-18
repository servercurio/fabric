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

package com.servercurio.fabric.core.collections;

import com.servercurio.fabric.core.security.*;
import com.servercurio.fabric.core.serialization.ObjectId;
import com.servercurio.fabric.core.serialization.SerializationAware;
import com.servercurio.fabric.core.serialization.Version;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import java.util.Collections;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;

public class MerkleMapNode<K extends SerializationAware, V extends SerializationAware> extends AbstractHashable implements SerializationAware, Map.Entry<K, V> {

    public static final ObjectId OBJECT_ID = new ObjectId(1, 42215);
    public static final SortedSet<Version> VERSIONS;

    static {
        final TreeSet<Version> versionSet = new TreeSet<>();
        versionSet.add(new Version(1, 0, 0));

        VERSIONS = Collections.unmodifiableSortedSet(versionSet);
    }


    private final K key;
    private V value;


    public MerkleMapNode(final K key, final V value) {
        this(key, value, HashAlgorithm.SHA_384);
    }

    public MerkleMapNode(final K key, final V value, final HashAlgorithm algorithm) {
        this(key, value, algorithm, Cryptography.getDefaultInstance());
    }

    public MerkleMapNode(final K key, final V value, final HashAlgorithm algorithm, final Cryptography cryptography) {
        super(algorithm, cryptography);

        if (key == null) {
            throw new IllegalArgumentException("key");
        }

        this.key = key;
        this.value = value;
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
    public K getKey() {
        return key;
    }

    @Override
    public V getValue() {
        return value;
    }

    @Override
    public V setValue(final V value) {
        if (this.value == value) {
            return this.value;
        }

        final V oldValue = this.value;
        this.value = value;
        setHash(null);

        return oldValue;
    }


    @Override
    protected Hash computeHash(final HashAlgorithm algorithm, final Cryptography cryptography) {
        final Hash keyHash = cryptography.digestSync(algorithm, key);
        final Hash valueHash = cryptography.digestSync(algorithm, value);

        return cryptography.digestSync(algorithm, keyHash, valueHash);
    }


    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }

        if (o == null || (getClass() != o.getClass() && !o.getClass().isAssignableFrom(getClass()))) {
            return false;
        }

        final MerkleMapNode<?, ?> that = (MerkleMapNode<?, ?>) o;

        return new EqualsBuilder()
                .append(key, that.key)
                .append(value, that.value)
                .isEquals();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37)
                .append(key)
                .append(value)
                .toHashCode();
    }
}
