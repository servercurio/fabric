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

import com.servercurio.fabric.core.security.Hash;
import com.servercurio.fabric.core.serialization.SerializationAware;

abstract class AbstractMerkleNode<T extends SerializationAware> implements MerkleNode<T> {

    private MerkleTree<T> tree;
    private Hash hash;

    private MerkleInternalNode<T> parent;

    protected AbstractMerkleNode(final MerkleTree<T> tree) {
        this.tree = tree;
        this.hash = null;
    }

    protected AbstractMerkleNode(final MerkleTree<T> tree, final MerkleInternalNode<T> parent) {
        this(tree);

        setParent(parent);
    }

    @Override
    public Hash getHash() {
        return hash;
    }

    @Override
    public void setHash(final Hash hash) {
        if (this.hash == hash) {
            return;
        }

        if (parent != null && parent.hasHash()) {
            parent.setHash(null);
        }

        this.hash = hash;
    }

    @Override
    public boolean hasHash() {
        return hash != null;
    }

    @Override
    public MerkleInternalNode<T> getParent() {
        return parent;
    }

    @Override
    public void setParent(final MerkleInternalNode<T> parent) {
        if (this.parent == parent) {
            return;
        }

        setHash(null);

        if (parent != null && parent.hasHash()) {
            parent.setHash(null);
        }

        this.parent = parent;
    }

    @Override
    public MerkleTree<T> getTree() {
        return tree;
    }

}
