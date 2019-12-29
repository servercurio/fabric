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
        return super.add(t);
    }


    /**
     * Returns an iterator over the elements contained in this collection.
     *
     * @return an iterator over the elements contained in this collection
     */
    @Override
    public Iterator<T> iterator() {
        return new MerkleIterator(this);
    }

    @Override
    public int size() {
        return leafCount;
    }

    private class MerkleIterator implements Iterator<T> {

        private MerkleTree<T> parent;

        public MerkleIterator(final MerkleTree<T> parent) {
            this.parent = parent;
        }

        /**
         * Returns {@code true} if the iteration has more elements. (In other words, returns {@code true} if {@link
         * #next} would return an element rather than throwing an exception.)
         *
         * @return {@code true} if the iteration has more elements
         */
        @Override
        public boolean hasNext() {
            return false;
        }

        /**
         * Returns the next element in the iteration.
         *
         * @return the next element in the iteration
         * @throws NoSuchElementException if the iteration has no more elements
         */
        @Override
        public T next() {
            return null;
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

        }
    }
}
