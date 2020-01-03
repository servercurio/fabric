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

import com.servercurio.fabric.core.security.Cryptography;
import com.servercurio.fabric.core.security.CryptographyException;
import com.servercurio.fabric.core.security.Hash;
import com.servercurio.fabric.core.security.HashAlgorithm;
import com.servercurio.fabric.core.serialization.ObjectId;
import com.servercurio.fabric.core.serialization.SerializationAware;
import com.servercurio.fabric.core.serialization.Version;

import java.util.Collections;
import java.util.SortedSet;
import java.util.TreeSet;

public class MerkleLeafNode<T extends SerializationAware> extends AbstractMerkleNode<T> {

    public static final ObjectId OBJECT_ID = new ObjectId(1, 39146);
    public static final SortedSet<Version> VERSIONS;

    private T value;

    static {
        final TreeSet<Version> versionSet = new TreeSet<>();
        versionSet.add(new Version(1, 0, 0));

        VERSIONS = Collections.unmodifiableSortedSet(versionSet);
    }

    public MerkleLeafNode(final MerkleTree<T> tree) {
        super(tree);
    }

    public MerkleLeafNode(final MerkleTree<T> tree, final MerkleInternalNode<T> parent) {
        super(tree, parent);
    }

    public MerkleLeafNode(final MerkleTree<T> tree, final T value) {
        super(tree);

        setValue(value);
    }

    public MerkleLeafNode(final MerkleTree<T> tree, final MerkleInternalNode<T> parent, final T value) {
        super(tree, parent);

        setValue(value);
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
    public Hash getHash() {
        if (super.getHash() != null) {
            return super.getHash();
        }

        final Cryptography cryptography = getTree().getCryptography();
        final HashAlgorithm algorithm = getTree().getHashAlgorithm();

        try {
            final Hash valueHash = cryptography.digestSync(algorithm, value);

            setHash(valueHash);
            return valueHash;
        } catch (CryptographyException ex) {
            throw new MerkleTreeException(ex);
        }
    }

    public T getValue() {
        return value;
    }

    public void setValue(final T value) {
        if (this.value == value) {
            return;
        }

        this.value = value;
        setHash(null);
    }
}
