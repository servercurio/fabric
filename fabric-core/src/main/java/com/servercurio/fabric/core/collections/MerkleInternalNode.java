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
import com.servercurio.fabric.core.serialization.SerializationAware;

public class MerkleInternalNode<T extends SerializationAware> extends AbstractMerkleNode<T> {

    private MerkleNode<T> leftChild;
    private MerkleNode<T> rightChild;


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
    protected Hash computeHash(final HashAlgorithm algorithm, final Cryptography cryptography) {
        final Hash leftHash = (leftChild != null) ? leftChild.getHash() : null;
        final Hash rightHash = (rightChild != null) ? rightChild.getHash() : null;

        return cryptography.digestSync(algorithm, leftHash, rightHash);
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

}
