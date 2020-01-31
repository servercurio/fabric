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

import java.util.*;

class MerkleIterator<T extends SerializationAware> implements Iterator<T> {

    private final MerkleTree<T> tree;
    private LinkedList<MerkleNode<T>> dfsStack;
//    private Set<MerkleNode<T>> visitedSet;

    private MerkleLeafNode<T> lastReturned;
    private int expectedModificationCount;

    public MerkleIterator(final MerkleTree<T> tree) {
        this.tree = tree;
        this.dfsStack = new LinkedList<>();
//        this.visitedSet = new HashSet<>(tree.getNodeCount());

        this.dfsStack.addFirst(tree.getRoot());
        this.expectedModificationCount = tree.getModificationCount();
    }

    /**
     * Returns {@code true} if the iteration has more elements. (In other words, returns {@code true} if {@link #next}
     * would return an element rather than throwing an exception.)
     *
     * @return {@code true} if the iteration has more elements
     */
    @Override
    public boolean hasNext() {
        return !tree.isEmpty() && !dfsStack.isEmpty();
    }

    /**
     * Returns the next element in the iteration.
     *
     * @return the next element in the iteration
     * @throws NoSuchElementException if the iteration has no more elements
     */
    @Override
    public T next() {
        checkForComodification();

        if (!hasNext()) {
            throw new NoSuchElementException();
        }

        MerkleNode<T> current = dfsStack.pollLast();

        while (current instanceof MerkleInternalNode) {

//            if (visitedSet.contains(current)) {
//                current = dfsStack.pollFirst();
//                continue;
//            }

            final MerkleInternalNode<T> currentInternal = (MerkleInternalNode<T>) current;
//            visitedSet.add(current);

            if (currentInternal.getLeftChild() != null /* && !visitedSet
                    .contains(currentInternal.getLeftChild()) */ ) {
                dfsStack.addFirst(currentInternal.getLeftChild());
            }

            if (currentInternal.getRightChild() != null /* && !visitedSet
                    .contains(currentInternal.getRightChild())*/ ) {
                dfsStack.addFirst(currentInternal.getRightChild());
            }

            current = dfsStack.pollLast();
        }

//        if (!(current instanceof MerkleLeafNode)) {
//            throw new NoSuchElementException();
//        }

//        visitedSet.add(current);
        lastReturned = ((MerkleLeafNode<T>) current);

        if (lastReturned == null) {
            throw new NoSuchElementException();
        }

        return lastReturned.getValue();
    }

    /**
     * Removes from the underlying collection the last element returned by this iterator (optional operation). This
     * method can be called only once per call to {@link #next}.
     * <p>
     * The behavior of an iterator is unspecified if the underlying collection is modified while the iteration is in
     * progress in any way other than by calling this method, unless an overriding class has specified a concurrent
     * modification policy.
     * <p>
     * The behavior of an iterator is unspecified if this method is called after a call to the {@link #forEachRemaining
     * forEachRemaining} method.
     *
     * @throws UnsupportedOperationException if the {@code remove} operation is not supported by this iterator
     * @throws IllegalStateException         if the {@code next} method has not yet been called, or the {@code remove}
     *                                       method has already been called after the last call to the {@code next}
     *                                       method
     * @implSpec The default implementation throws an instance of {@link UnsupportedOperationException} and performs no
     * other action.
     */
    @Override
    public void remove() {
        checkForComodification();

        if (lastReturned == null) {
            throw new IllegalStateException();
        }

        final MerkleInternalNode<T> rightMostParent = tree.getRightMostLeafNode().getParent();
        final MerkleInternalNode<T> lastReturnedParent = lastReturned.getParent();
        final boolean rightMostOnLeft = (rightMostParent.getLeftChild() == tree.getRightMostLeafNode());

        final boolean internalNodeRemoved = collapseRightMostPath(rightMostParent, rightMostOnLeft);
        replaceNode(lastReturnedParent);


        tree.setLeafCount(tree.getLeafCount() - 1);
        final int nodeDelta = (internalNodeRemoved) ? 2 : 1;
        tree.setNodeCount(tree.getNodeCount() - nodeDelta);
        lastReturned = null;

        reassignRightMostNode();

        expectedModificationCount++;
        tree.setModificationCount(tree.getModificationCount() + 1);
    }

    private boolean collapseRightMostPath(final MerkleInternalNode<T> rightMostParent, final boolean rightMostOnLeft) {
        boolean internalNodeRemoved = false;

        if (rightMostParent == tree.getRoot()) {
            if (rightMostOnLeft) {
                tree.getRoot().setLeftChild(null);
            } else {
                tree.getRoot().setRightChild(null);
            }
        } else {
            final MerkleNode<T> rightMostLeftChild = rightMostParent.getLeftChild();

            rightMostParent.setLeftChild(null);
            rightMostParent.setRightChild(null);

            if (rightMostLeftChild != tree.getRightMostLeafNode()) {
                if (rightMostParent.getParent().getLeftChild() == rightMostParent) {
                    rightMostParent.getParent().setLeftChild(rightMostLeftChild);
                } else {
                    rightMostParent.getParent().setRightChild(rightMostLeftChild);
                }
            }

            rightMostParent.setParent(null);
            internalNodeRemoved = true;
        }

        tree.getRightMostLeafNode().setParent(null);

        return internalNodeRemoved;
    }

    private void replaceNode(final MerkleInternalNode<T> lastReturnedParent) {
        if (lastReturned != tree.getRightMostLeafNode()) {
            final boolean lastReturnedOnLeft = lastReturnedParent.getLeftChild() == lastReturned;

            if (lastReturnedOnLeft) {
                lastReturnedParent.setLeftChild(tree.getRightMostLeafNode());
            } else {
                lastReturnedParent.setRightChild(tree.getRightMostLeafNode());
            }

            dfsStack.addFirst(tree.getRightMostLeafNode());
            lastReturned.setParent(null);
        }
    }

    private void reassignRightMostNode() {
        if (tree.getLeafCount() > 2) {
            final MerkleNode<T> newRightNode =
                    new TreeNavigator<>(tree.getRoot().getTree()).nodeAt(tree.getNodeCount());

//            if (newRightNode instanceof MerkleInternalNode) {
//                throw new MerkleTreeException("Illegal internal node returned when leaf node expected");
//            }

            tree.setRightMostLeafNode((MerkleLeafNode<T>) newRightNode);
        } else {
            final MerkleLeafNode<T> newRightNode = (tree.getLeafCount() == 2) ?
                                                   (MerkleLeafNode<T>) tree.getRoot().getRightChild() :
                                                   (MerkleLeafNode<T>) tree.getRoot().getLeftChild();

            tree.setRightMostLeafNode(newRightNode);
        }
    }

    private void checkForComodification() {
        if (tree.getModificationCount() != expectedModificationCount) {
            throw new ConcurrentModificationException();
        }
    }
}
