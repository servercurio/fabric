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

import com.servercurio.fabric.core.serialization.SerializationAware;

class TreeNavigator<T extends SerializationAware> extends BitNavigator {

    private MerkleTree<T> tree;

    public TreeNavigator(final MerkleTree<T> tree) {
        super(tree.getNodeCount());
        this.tree = tree;
    }

    public MerkleTree<T> getTree() {
        return tree;
    }

    public MerkleNode<T> nodeAt(final long nodePosition) {
        navigateTo(nodePosition);
        return fetch();
    }

    public MerkleNode<T> insertAt() {
        insertion();
        return fetch();
    }

    public MerkleNode<T> rightMostNode() {
        rightMostLeaf();
        return fetch();
    }

    private MerkleNode<T> fetch() {
        NavigationStep step = nextStep();
        MerkleNode<T> current = tree.getRoot();

        while (step != NavigationStep.COMPLETE && current != null) {
            if (current instanceof MerkleInternalNode) {
                MerkleInternalNode<T> internalNode = (MerkleInternalNode<T>) current;

                if (step == NavigationStep.RIGHT) {
                    current = internalNode.getRightChild();
                } else {
                    current = internalNode.getLeftChild();
                }

                step = nextStep();
            } else {
                break;
            }
        }

        return current;
    }
}
