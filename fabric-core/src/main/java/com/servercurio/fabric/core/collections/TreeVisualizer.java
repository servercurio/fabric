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
import edu.uci.ics.jung.graph.OrderedKAryTree;

import javax.swing.*;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

public class TreeVisualizer<T extends SerializationAware> {

    private static final String LEFT_TREE_HEADER = "Left Tree";
    private static final String RIGHT_TREE_HEADER = "Right Tree";
    private static final String TREE_HEADER = "Tree";
    private static final String LEFT = "L";
    private static final String RIGHT = "R";

    private static final String HYPHEN = "-";
    private static final String UNDERSCORE = "_";
    private static final String FORWARD_SLASH = "/";
    private static final String BACK_SLASH = "\\";
    private static final String TILDE = "~";
    private static final String PIPE = "|";
    private static final String SPACE = " ";
    private static final String TAB = "\t";
    private static final String NEWLINE = "\n";
    private static final String EMPTY = "";

    private MerkleTree<T> leftTree;
    private MerkleTree<T> rightTree;


    public TreeVisualizer(final MerkleTree<T> leftTree) {
        this(leftTree, null);
    }

    public TreeVisualizer(final MerkleTree<T> leftTree, final MerkleTree<T> rightTree) {
        if (leftTree == null) {
            throw new IllegalArgumentException("leftTree");
        }

        this.leftTree = leftTree;
        this.rightTree = rightTree;
    }

    public MerkleTree<T> getLeftTree() {
        return leftTree;
    }

    public MerkleTree<T> getRightTree() {
        return rightTree;
    }


    public void render() {
//        if (rendered) {
//            return;
//        }
//
//        renderTree(leftTree, (rightTree != null) ? LEFT_TREE_HEADER : TREE_HEADER);
//
//        if (rightTree != null) {
//            renderTree(rightTree, RIGHT_TREE_HEADER);
//        }

        final boolean dualTreeView = (rightTree != null);
        final JFrame window = new JFrame();
    }

    private OrderedKAryTree<Vertex<T>, Edge<T>> renderTree(final MerkleTree<T> merkleTree) {
        final OrderedKAryTree<Vertex<T>, Edge<T>> renderTree = new OrderedKAryTree<>(2);
        final Map<MerkleNode<T>, Vertex<T>> vertexCache = new HashMap<>();

        final Deque<MerkleNode<T>> dfsQueue = new LinkedList<>();

        dfsQueue.push(merkleTree.getRoot());

        while (!dfsQueue.isEmpty()) {
            final MerkleNode<T> node = dfsQueue.pop();

            visit(vertexCache, renderTree, node);

            if (node.getLeftChild() != null) {
                dfsQueue.push(node.getLeftChild());
            }

            if (node.getRightChild() != null) {
                dfsQueue.push(node.getRightChild());
            }

        }

        return renderTree;
    }

    private void visit(final Map<MerkleNode<T>, Vertex<T>> vertexCache, final OrderedKAryTree<Vertex<T>, Edge<T>> tree,
                       final MerkleNode<T> node) {

        if (node.getParent() == null) {
            vertexCache.putIfAbsent(node, new Vertex<>(null, node.getHash()));
            return;
        }

        final Vertex<T> parentVertex =
                vertexCache.putIfAbsent(node.getParent(), new Vertex<>(null, node.getParent().getHash()));

        Vertex<T> vertex;

        if (node instanceof MerkleLeafNode) {
            final MerkleLeafNode<T> leafNode = (MerkleLeafNode<T>) node;
            vertex = vertexCache.putIfAbsent(node, new Vertex<>(leafNode.getValue(), leafNode.getHash()));
        } else {
            vertex = vertexCache.putIfAbsent(node, new Vertex<>(null, node.getHash()));
        }

        tree.addEdge(new Edge<>(parentVertex, vertex, node.getParent().getLeftChild() == node), parentVertex,
                     vertex);
    }

//    public void print(final PrintWriter writer) {
//        render();
//        writer.println(output.toString());
//        writer.flush();
//    }
//
//    private void renderTree(final MerkleTree<T> tree, final String header) {
//        final Deque<List<MerkleNode<T>>> renderQueue = new LinkedList<>();
//        renderLevel(renderQueue, Collections.singletonList(tree.getRoot()));
//
//        final Deque<StringBuilder> printQueue = new LinkedList<>();
//        int maxWidth = 0;
//        int depth = 0;
//
//        while (!renderQueue.isEmpty()) {
//            final List<MerkleNode<T>> level = renderQueue.pop();
//            final StringBuilder printedLevel = printLevel(level, depth, renderQueue.isEmpty());
//            maxWidth = Math.max(maxWidth, printedLevel.length());
//            printQueue.push(printedLevel);
//            depth++;
//        }
//
//        output.append(repeat(HYPHEN, maxWidth)).append(NEWLINE)
//              .append(repeat(SPACE, (maxWidth / 2) - (header.length() / 2))).append(header).append(NEWLINE)
//              .append(repeat(HYPHEN, maxWidth)).append(NEWLINE).append(NEWLINE);
//
//        while (!printQueue.isEmpty()) {
//            final StringBuilder line = printQueue.pop();
//            output.append(line.toString());
//        }
//
//        output.append(NEWLINE).append(NEWLINE);
//    }
//
//    private void renderLevel(final Deque<List<MerkleNode<T>>> renderQueue, final List<MerkleNode<T>> nodes) {
//        renderQueue.push(nodes);
//
//        final List<MerkleNode<T>> nextLevel = new ArrayList<>();
//
//        for (MerkleNode<T> node : nodes) {
//            if (node.getLeftChild() != null) {
//                nextLevel.add(node.getLeftChild());
//            }
//
//            if (node.getRightChild() != null) {
//                nextLevel.add(node.getRightChild());
//            }
//        }
//
//        if (!nextLevel.isEmpty()) {
//            renderLevel(renderQueue, nextLevel);
//        }
//    }
//
//    private StringBuilder printLevel(final List<MerkleNode<T>> level, final int depth, final boolean top) {
//        final StringBuilder sb = new StringBuilder();
//        final int tabSepCount = Math.max(1, depth * (level.size() - 1));
//        final String tabSep = repeat(TAB, tabSepCount);
//        final String slashLevelSep = repeat(TAB, tabSepCount + 1);
//
//        if (!top) {
//            sb.append(NEWLINE);
//
//            if (depth > 0) {
//                sb.append(tabSep);
//            }
//
//
//            for (int i = 0; i < level.size(); i++) {
//                sb.append(PIPE).append(slashLevelSep);
//            }
//
//            sb.append(NEWLINE).append(NEWLINE);
//        }
//
//        if (depth > 0) {
//            sb.append(tabSep);
//        }
//
//        for (MerkleNode<T> node : level) {
//            sb.append(node.toString()).append(tabSep);
//        }
//
//        sb.append(NEWLINE);
//
//        return sb;
//    }

    private static class Edge<T extends SerializationAware> {

        private boolean leftEdge;
        private Vertex<T> parent;
        private Vertex<T> child;

        public Edge(final Vertex<T> parent, final Vertex<T> child, final boolean leftEdge) {
            this.parent = parent;
            this.child = child;
            this.leftEdge = leftEdge;
        }

        public Vertex<T> getParent() {
            return parent;
        }

        public Vertex<T> getChild() {
            return child;
        }

        @Override
        public String toString() {
            return (leftEdge) ? LEFT : RIGHT;
        }
    }

    private static class Vertex<T extends SerializationAware> {

        private T value;
        private Hash hash;

        public Vertex(final T value, final Hash hash) {
            this.value = value;
            this.hash = hash;
        }

        public T getValue() {
            return value;
        }

        public Hash getHash() {
            return hash;
        }

        @Override
        public String toString() {
            String strValue;

            if (value instanceof Hash) {
                strValue = ((Hash) value).getPrefix();
            } else if (value != null) {
                strValue = value.toString();
            } else {
                strValue = hash.getPrefix();
            }

            return strValue;
        }
    }
}
