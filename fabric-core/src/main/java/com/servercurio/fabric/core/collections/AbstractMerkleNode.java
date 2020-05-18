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

import com.servercurio.fabric.core.security.AbstractHashable;
import com.servercurio.fabric.core.security.Hash;
import com.servercurio.fabric.core.serialization.SerializationAware;
import org.apache.commons.lang3.builder.ToStringBuilder;

import java.util.Objects;

abstract class AbstractMerkleNode<T extends SerializationAware> extends AbstractHashable implements MerkleNode<T> {

    private MerkleTree<T> tree;

    private MerkleInternalNode<T> parent;

    protected AbstractMerkleNode(final MerkleTree<T> tree) {
        super(tree.getHashAlgorithm(), tree.getCryptography());
        this.tree = tree;
    }

    protected AbstractMerkleNode(final MerkleTree<T> tree, final MerkleInternalNode<T> parent) {
        this(tree);

        setParent(parent);
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

    @Override
    public String toString() {
       final Hash hash = getHash();
       final StringBuilder sb = new StringBuilder();

       if (hash == null || hash.getValue() == null || hash.getValue().length < 4) {
           return super.toString();
       }

       final byte[] hashValue = hash.getValue();

       for (int i = 0; i < 4; i++) {
           sb.append(String.format("%02x", hashValue[i]));
       }

       return sb.toString();
    }
}
