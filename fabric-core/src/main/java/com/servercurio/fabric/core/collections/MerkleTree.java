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
import com.servercurio.fabric.core.security.Hash;
import com.servercurio.fabric.core.security.HashAlgorithm;
import com.servercurio.fabric.core.serialization.ObjectId;
import com.servercurio.fabric.core.serialization.SerializationAware;
import com.servercurio.fabric.core.serialization.Version;

import java.util.*;

public class MerkleTree<T extends SerializationAware> extends AbstractCollection<T> implements SerializationAware {

    public static final ObjectId OBJECT_ID = new ObjectId(1, 39144);
    public static final SortedSet<Version> VERSIONS;

    private HashAlgorithm hashAlgorithm;
    private Cryptography cryptography;

    private MerkleInternalNode<T> root;
    private MerkleLeafNode<T> rightMostLeafNode;

    private int nodeCount;
    private int leafCount;

    private int modificationCount;

    static {
        final TreeSet<Version> versionSet = new TreeSet<>();
        versionSet.add(new Version(1, 0, 0));

        VERSIONS = Collections.unmodifiableSortedSet(versionSet);
    }

    public MerkleTree() {
        super();

        this.hashAlgorithm = HashAlgorithm.SHA_384;
        this.cryptography = Cryptography.getDefaultInstance();
        this.root = new MerkleInternalNode<>(this);
        this.rightMostLeafNode = null;
        this.leafCount = 0;
        this.nodeCount = 1;
        this.modificationCount = 0;
    }

    public MerkleTree(final HashAlgorithm hashAlgorithm) {
        this();

        if (hashAlgorithm == null || hashAlgorithm == HashAlgorithm.NONE) {
            throw new IllegalArgumentException("hashAlgorithm");
        }

        this.hashAlgorithm = hashAlgorithm;
    }

    public MerkleTree(final HashAlgorithm hashAlgorithm, final Cryptography cryptography) {
        this(hashAlgorithm);

        if (cryptography == null) {
            throw new IllegalArgumentException("cryptography");
        }

        this.cryptography = cryptography;
    }

    public MerkleTree(final Collection<T> other) {
        this(other, HashAlgorithm.SHA_384, Cryptography.getDefaultInstance());
    }

    public MerkleTree(final Collection<T> other, final HashAlgorithm hashAlgorithm) {
        this(other, hashAlgorithm, Cryptography.getDefaultInstance());
    }

    public MerkleTree(final Collection<T> other, final HashAlgorithm hashAlgorithm, final Cryptography cryptography) {
        this(hashAlgorithm, cryptography);

        if (other == null) {
            throw new IllegalArgumentException("other");
        }

        rebuild(other);
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

    public HashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }

    public Cryptography getCryptography() {
        return cryptography;
    }

    public MerkleInternalNode<T> getRoot() {
        return root;
    }

    public Hash getHash() {
        return (root != null) ? root.getHash() : null;
    }

    protected int getNodeCount() {
        return nodeCount;
    }

    protected void setNodeCount(final int nodeCount) {
        this.nodeCount = nodeCount;
    }

    protected MerkleLeafNode<T> getRightMostLeafNode() {
        return rightMostLeafNode;
    }

    protected void setRightMostLeafNode(final MerkleLeafNode<T> rightMostLeafNode) {
        this.rightMostLeafNode = rightMostLeafNode;
    }

    protected int getLeafCount() {
        return leafCount;
    }

    protected void setLeafCount(final int leafCount) {
        this.leafCount = leafCount;
    }

    protected int getModificationCount() {
        return modificationCount;
    }

    protected void setModificationCount(final int modificationCount) {
        this.modificationCount = modificationCount;
    }

    /**
     * {@inheritDoc}
     *
     * @param t the element to be added
     * @throws UnsupportedOperationException {@inheritDoc}
     * @throws ClassCastException            {@inheritDoc}
     * @throws NullPointerException          {@inheritDoc}
     * @throws IllegalArgumentException      {@inheritDoc}
     * @throws IllegalStateException         {@inheritDoc}
     */
    @Override
    public boolean add(final T t) {
        final MerkleLeafNode<T> newLeafNode = new MerkleLeafNode<>(this, t);

        if (size() < 2) {
            if (size() == 0) {
                this.root.setLeftChild(newLeafNode);
            } else {
                this.root.setRightChild(newLeafNode);
            }

            leafCount++;
            nodeCount++;
            rightMostLeafNode = newLeafNode;
            modificationCount++;
            return true;
        }

        final TreeNavigator<T> navigator = new TreeNavigator<>(this);
        final MerkleNode<T> insertAtNode = navigator.insertAt();

//        if (insertAtNode instanceof MerkleInternalNode) {
//            throw new MerkleTreeException("Illegal node insertion was attempted at an internal node");
//        }

        final MerkleInternalNode<T> interimNode = new MerkleInternalNode<>(this);
        final MerkleInternalNode<T> insertAtParent = insertAtNode.getParent();
        final boolean insertAtOnLeft = insertAtParent.getLeftChild() == insertAtNode;

        interimNode.setLeftChild(insertAtNode);
        interimNode.setRightChild(newLeafNode);

        if (insertAtOnLeft) {
            insertAtParent.setLeftChild(interimNode);
        } else {
            insertAtParent.setRightChild(interimNode);
        }

        leafCount++;
        nodeCount += 2;
        rightMostLeafNode = newLeafNode;
        modificationCount++;
        return true;
    }


    /**
     * Returns an iterator over the elements contained in this collection.
     *
     * @return an iterator over the elements contained in this collection
     */
    @Override
    public Iterator<T> iterator() {
        return new MerkleIterator<>(this);
    }

    @Override
    public int size() {
        return leafCount;
    }


    protected void reassignRightMostNode() {
        if (getLeafCount() > 2) {
            final MerkleNode<T> newRightNode =
                    new TreeNavigator<>(getRoot().getTree()).nodeAt(getNodeCount());

//            if (newRightNode instanceof MerkleInternalNode) {
//                throw new MerkleTreeException("Illegal internal node returned when leaf node expected");
//            }

            setRightMostLeafNode((MerkleLeafNode<T>) newRightNode);
        } else {
            final MerkleLeafNode<T> newRightNode = (getLeafCount() == 2) ?
                                                   (MerkleLeafNode<T>) getRoot().getRightChild() :
                                                   (MerkleLeafNode<T>) getRoot().getLeftChild();

            setRightMostLeafNode(newRightNode);
        }
    }

    private void rebuild(final Collection<T> values) {
        if (values == null) {
            throw new IllegalArgumentException("values");
        }

        if (values.isEmpty()) {
            return;
        }

        final List<MerkleNode<T>> leafNodes = new ArrayList<>();
        this.setLeafCount(values.size());

        for (T value : values) {
            leafNodes.add(new MerkleLeafNode<>(this, value));
        }


        List<MerkleNode<T>> currentLevel = buildNextLevel(leafNodes);

        while (currentLevel.size() > 1) {
            currentLevel = buildNextLevel(currentLevel);
        }

        this.root = (MerkleInternalNode<T>) currentLevel.get(0);
        reassignRightMostNode();
    }

    private List<MerkleNode<T>> buildNextLevel(final List<MerkleNode<T>> currentLevel) {
        final List<MerkleNode<T>> nextLevel = new ArrayList<>();

        MerkleInternalNode<T> currentPartialNode = null;
        final Iterator<MerkleNode<T>> iter = currentLevel.iterator();

        while (iter.hasNext()) {
            final MerkleNode<T> node = iter.next();

            if (currentPartialNode == null) {
                if (currentLevel.size() > 2 && !iter.hasNext()) {
                    nextLevel.add(node);
                } else {
                    currentPartialNode = new MerkleInternalNode<>(this);
                    currentPartialNode.setLeftChild(node);
                    this.setNodeCount(this.getNodeCount() + 1);
                    nextLevel.add(currentPartialNode);

                }
            } else {
                currentPartialNode.setRightChild(node);
                this.setNodeCount(this.getNodeCount() + 1);
                currentPartialNode = null;
            }


        }

        return nextLevel;
    }
}
