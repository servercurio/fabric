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

class MerkleInternalNode<T extends SerializationAware> extends AbstractMerkleNode<T> {

    public static final ObjectId OBJECT_ID = new ObjectId(1, 39145);
    public static final SortedSet<Version> VERSIONS;

    private MerkleNode<T> leftChild;
    private MerkleNode<T> rightChild;

    static {
        final TreeSet<Version> versionSet = new TreeSet<>();
        versionSet.add(new Version(1, 0, 0));

        VERSIONS = Collections.unmodifiableSortedSet(versionSet);
    }

    public MerkleInternalNode(final MerkleTree<T> tree) {
        super(tree);
    }

    public MerkleInternalNode(final MerkleTree<T> tree, final MerkleInternalNode<T> parent) {
        super(tree, parent);
    }

    public MerkleInternalNode(final MerkleTree<T> tree, final MerkleNode<T> leftChild, final MerkleNode<T> rightChild) {
        super(tree);

        setLeftChild(leftChild);
        setRightChild(rightChild);
    }

    public MerkleInternalNode(final MerkleTree<T> tree, final MerkleInternalNode<T> parent,
                              final MerkleNode<T> leftChild, final MerkleNode<T> rightChild) {
        super(tree, parent);

        setLeftChild(leftChild);
        setRightChild(rightChild);
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

        if (leftChild == null && rightChild == null) {
            return null;
        }

        final Cryptography cryptography = getTree().getCryptography();
        final HashAlgorithm algorithm = getTree().getHashAlgorithm();
        final Hash leftHash = (leftChild != null) ? leftChild.getHash() : null;
        final Hash rightHash = (rightChild != null) ? rightChild.getHash() : null;

        try {
            final Hash nodeHash = cryptography.digestSync(algorithm, leftHash, rightHash);
            setHash(nodeHash);

            return nodeHash;
        } catch (CryptographyException ex) {
            throw new MerkleTreeException(ex);
    }
    }

    public MerkleNode<T> getLeftChild() {
        return leftChild;
    }

    public void setLeftChild(final MerkleNode<T> leftChild) {
        if (this.leftChild == leftChild) {
            return;
        }

        this.leftChild = leftChild;

        if (leftChild == null) {
            setHash(null);
        } else {
            this.leftChild.setParent(this);
        }

    }

    public MerkleNode<T> getRightChild() {
        return rightChild;
    }

    public void setRightChild(final MerkleNode<T> rightChild) {
        if (this.rightChild == rightChild) {
            return;
        }

        this.rightChild = rightChild;

        if (rightChild == null) {
            setHash(null);
        } else {
            this.rightChild.setParent(this);
        }
    }

    public boolean isPartial() {
        return !isFull() && !isEmpty();
    }

    public boolean isEmpty() {
        return leftChild == null && rightChild == null;
    }

    public boolean isFull() {
        return leftChild != null && rightChild != null;
    }
}
