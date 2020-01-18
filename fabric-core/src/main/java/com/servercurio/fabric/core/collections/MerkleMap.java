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
import com.servercurio.fabric.core.security.Hashable;
import com.servercurio.fabric.core.serialization.ObjectId;
import com.servercurio.fabric.core.serialization.SerializationAware;
import com.servercurio.fabric.core.serialization.Version;

import java.util.*;

public class MerkleMap<K extends SerializationAware, V extends SerializationAware> extends AbstractMap<K, V>
        implements SerializationAware, Hashable {

    public static final ObjectId OBJECT_ID = new ObjectId(1, 42214);
    public static final SortedSet<Version> VERSIONS;

    static {
        final TreeSet<Version> versionSet = new TreeSet<>();
        versionSet.add(new Version(1, 0, 0));

        VERSIONS = Collections.unmodifiableSortedSet(versionSet);
    }

    private Cryptography cryptography;
    private HashAlgorithm algorithm;

    private Map<K, MerkleMapNode<K, V>> lookupMap;
    private MerkleTree<MerkleMapNode<K, V>> merkleTree;

    private Hash hash;

    private final EntrySetView entrySet = new EntrySetView();

    public MerkleMap() {
        this(HashAlgorithm.SHA_384);
    }

    public MerkleMap(final HashAlgorithm algorithm) {
        this(algorithm, Cryptography.getDefaultInstance());
    }

    public MerkleMap(final HashAlgorithm algorithm, final Cryptography cryptography) {
        this.algorithm = algorithm;
        this.cryptography = cryptography;
        this.merkleTree = new MerkleTree<>(algorithm, cryptography);
        this.lookupMap = new HashMap<>();
    }

    public Cryptography getCryptography() {
        return cryptography;
    }

    public HashAlgorithm getAlgorithm() {
        return algorithm;
    }

    public MerkleTree<MerkleMapNode<K, V>> getMerkleTree() {
        return merkleTree;
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
        if (hasHash()) {
            return hash;
        }

        hash = merkleTree.getHash();
        return hash;
    }

    @Override
    public void setHash(final Hash hash) {
        if (this.hash == hash) {
            return;
        }

        this.hash = hash;
    }

    @Override
    public boolean hasHash() {
        return hash != null;
    }

    /**
     * {@inheritDoc}
     *
     * @param key
     * @throws ClassCastException   {@inheritDoc}
     * @throws NullPointerException {@inheritDoc}
     */
    @Override
    public V get(final Object key) {
        final MerkleMapNode<K, V> node = lookupMap.get(key);

        return (node != null) ? node.getValue() : null;
    }

    /**
     * {@inheritDoc}
     *
     * @param key
     * @param value
     * @throws UnsupportedOperationException {@inheritDoc}
     * @throws ClassCastException            {@inheritDoc}
     * @throws NullPointerException          {@inheritDoc}
     * @throws IllegalArgumentException      {@inheritDoc}
     */
    @Override
    public V put(final K key, final V value) {
        final MerkleMapNode<K, V> node = new MerkleMapNode<>(key, value, algorithm, cryptography);
        final MerkleMapNode<K, V> prevNode = lookupMap.put(key, node);

        if (prevNode != null) {
            merkleTree.remove(prevNode);
        }

        merkleTree.add(node);
        setHash(null);

        return (prevNode != null) ? prevNode.getValue() : null;
    }

    /**
     * {@inheritDoc}
     *
     * @param key
     * @throws UnsupportedOperationException {@inheritDoc}
     * @throws ClassCastException            {@inheritDoc}
     * @throws NullPointerException          {@inheritDoc}
     */
    @Override
    public V remove(final Object key) {
        if (!lookupMap.containsKey(key)) {
            return null;
        }

        final MerkleMapNode<K, V> oldValue = lookupMap.remove(key);
        merkleTree.remove(oldValue);

        setHash(null);
        return oldValue.getValue();
    }

    /**
     * {@inheritDoc}
     *
     * @param key
     * @throws ClassCastException   {@inheritDoc}
     * @throws NullPointerException {@inheritDoc}
     */
    @Override
    public boolean containsKey(final Object key) {
        return lookupMap.containsKey(key);
    }

    @Override
    public Set<Entry<K, V>> entrySet() {
        return entrySet;
    }

    private class EntrySetView extends AbstractSet<Map.Entry<K, V>> {

        @Override
        public Iterator<Map.Entry<K, V>> iterator() {
            return new Itr(merkleTree.iterator());
        }

        @Override
        public int size() {
            return merkleTree.size();
        }

    }

    private class Itr implements Iterator<Map.Entry<K, V>> {

        private final Iterator<MerkleMapNode<K, V>> iter;
        private MerkleMapNode<K, V> lastReturned;

        public Itr(final Iterator<MerkleMapNode<K, V>> iter) {
            this.iter = iter;
        }

        @Override
        public boolean hasNext() {
            return iter.hasNext();
        }


        @Override
        public Map.Entry<K, V> next() {
            if (!hasNext()) {
                throw new NoSuchElementException();
            }

            lastReturned = iter.next();
            return lastReturned;
        }


        @Override
        public void remove() {
            if (lastReturned == null) {
                throw new IllegalStateException();
            }

            lookupMap.remove(lastReturned.getKey());
            iter.remove();

            setHash(null);

            lastReturned = null;
        }
    }
}
