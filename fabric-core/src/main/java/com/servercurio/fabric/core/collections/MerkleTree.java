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
    }

    public MerkleTree(final HashAlgorithm hashAlgorithm) {
        this();

        if (hashAlgorithm == null || HashAlgorithm.NONE.equals(hashAlgorithm)) {
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

        addAll(other);
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
            return true;
        }

        final TreeNavigator<T> navigator = new TreeNavigator<>(this);
        final MerkleNode<T> insertAtNode = navigator.insertAt();

        if (insertAtNode instanceof MerkleInternalNode) {
            throw new MerkleTreeException("Illegal node insertion was attempted at an internal node");
        }

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
        return true;
    }


    /**
     * Returns an iterator over the elements contained in this collection.
     *
     * @return an iterator over the elements contained in this collection
     */
    @Override
    public Iterator<T> iterator() {
        return new MerkleIterator();
    }

    @Override
    public int size() {
        return leafCount;
    }

    private class MerkleIterator implements Iterator<T> {

        private LinkedList<MerkleNode<T>> dfsStack;
        private Set<MerkleNode<T>> visitedSet;

        private MerkleLeafNode<T> lastReturned;

        public MerkleIterator() {
            this.dfsStack = new LinkedList<>();
            this.visitedSet = new HashSet<>(nodeCount);

            this.dfsStack.addFirst(root);
        }

        /**
         * Returns {@code true} if the iteration has more elements. (In other words, returns {@code true} if {@link
         * #next} would return an element rather than throwing an exception.)
         *
         * @return {@code true} if the iteration has more elements
         */
        @Override
        public boolean hasNext() {
            return !isEmpty() && !dfsStack.isEmpty();
        }

        /**
         * Returns the next element in the iteration.
         *
         * @return the next element in the iteration
         * @throws NoSuchElementException if the iteration has no more elements
         */
        @Override
        public T next() {
            if (!hasNext()) {
                throw new NoSuchElementException();
            }

            MerkleNode<T> current = dfsStack.pop();

            while (current instanceof MerkleInternalNode) {

                if (visitedSet.contains(current)) {
                    current = dfsStack.pollFirst();
                    continue;
                }

                final MerkleInternalNode<T> currentInternal = (MerkleInternalNode<T>) current;
                visitedSet.add(current);

                if (currentInternal.getRightChild() != null && !visitedSet.contains(currentInternal.getRightChild())) {
                    dfsStack.addFirst(currentInternal.getRightChild());
                }

                if (currentInternal.getLeftChild() != null && !visitedSet.contains(currentInternal.getLeftChild())) {
                    dfsStack.addFirst(currentInternal.getLeftChild());
                }

                current = dfsStack.pollFirst();
            }

            if (!(current instanceof MerkleLeafNode)) {
                throw new NoSuchElementException();
            }

            visitedSet.add(current);
            lastReturned = ((MerkleLeafNode<T>) current);

            return lastReturned.getValue();
        }

        /**
         * Removes from the underlying collection the last element returned by this iterator (optional operation).  This
         * method can be called only once per call to {@link #next}.
         * <p>
         * The behavior of an iterator is unspecified if the underlying collection is modified while the iteration is in
         * progress in any way other than by calling this method, unless an overriding class has specified a concurrent
         * modification policy.
         * <p>
         * The behavior of an iterator is unspecified if this method is called after a call to the {@link
         * #forEachRemaining forEachRemaining} method.
         *
         * @throws UnsupportedOperationException if the {@code remove} operation is not supported by this iterator
         * @throws IllegalStateException         if the {@code next} method has not yet been called, or the {@code
         *                                       remove} method has already been called after the last call to the
         *                                       {@code next} method
         * @implSpec The default implementation throws an instance of {@link UnsupportedOperationException} and performs
         * no other action.
         */
        @Override
        public void remove() {
            if (lastReturned == null) {
                throw new IllegalStateException();
            }

            final MerkleInternalNode<T> rightMostParent = rightMostLeafNode.getParent();
            final MerkleInternalNode<T> lastReturnedParent = lastReturned.getParent();
            final boolean rightMostOnLeft = (rightMostParent.getLeftChild() == rightMostLeafNode);

            boolean internalNodeRemoved = false;

            if (rightMostParent == root) {
                if (rightMostOnLeft) {
                    root.setLeftChild(null);
                } else {
                    root.setRightChild(null);
                }
            } else {
                final MerkleNode<T> rightMostLeftChild = rightMostParent.getLeftChild();

                rightMostParent.setLeftChild(null);
                rightMostParent.setRightChild(null);

                if (rightMostLeftChild != rightMostLeafNode) {
                    if (rightMostParent.getParent().getLeftChild() == rightMostParent) {
                        rightMostParent.getParent().setLeftChild(rightMostLeftChild);
                    } else {
                        rightMostParent.getParent().setRightChild(rightMostLeftChild);
                    }
                }

                rightMostParent.setParent(null);
                internalNodeRemoved = true;
            }

            rightMostLeafNode.setParent(null);

            if (lastReturned != rightMostLeafNode) {
                final boolean lastReturnedOnLeft = lastReturnedParent.getLeftChild() == lastReturned;

                if (lastReturnedOnLeft) {
                    lastReturnedParent.setLeftChild(rightMostLeafNode);
                } else {
                    lastReturnedParent.setRightChild(rightMostLeafNode);
                }

                lastReturned.setParent(null);
            }

            leafCount--;
            nodeCount -= (internalNodeRemoved) ? 2 : 1;
            lastReturned = null;

            if (leafCount > 2) {
                final MerkleNode<T> newRightNode = new TreeNavigator<>(root.getTree()).nodeAt(nodeCount);

                if (newRightNode instanceof MerkleInternalNode) {
                    throw new MerkleTreeException("Illegal internal node returned when leaf node expected");
                }

                rightMostLeafNode = (MerkleLeafNode<T>) newRightNode;
            } else {
                rightMostLeafNode = (leafCount == 2) ? (MerkleLeafNode<T>) root
                        .getRightChild() : (MerkleLeafNode<T>) root.getLeftChild();
            }
        }
    }
}
