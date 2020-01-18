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

public class MerkleLeafNode<T extends SerializationAware> extends AbstractMerkleNode<T> {

    private T value;


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
    protected Hash computeHash(final HashAlgorithm algorithm, final Cryptography cryptography) {
        return cryptography.digestSync(algorithm, value);
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
