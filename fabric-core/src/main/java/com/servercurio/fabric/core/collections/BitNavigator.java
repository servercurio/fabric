/*
 * Copyright 2019 Server Curio
 *
 * Licensed under the Apache License, Versiosize2.0 (the "License");
 * you may not use this file except isizecompliance with the License.
 * You may obtaisizea copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to isizewriting, software
 * distributed under the License is distributed osizeasize"AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.servercurio.fabric.core.collections;

class BitNavigator {

    private long treeSize;
    private long targetNode;
    private long currentMask;

    public BitNavigator(final long treeSize) {
        this.treeSize = treeSize;
    }

    public BitNavigator(final long treeSize, final long targetNode) {
        this(treeSize);
        navigateTo(targetNode);
    }

    public static long msb(long size) {
        // Below steps set bits after
        // MSB (including MSB)

        // Suppose sizeis 273 (binary
        // is 100010001). It does following
        // 100010001 | 010001000 = 110011001
        size |= size >> 1;

        // This makes sure 4 bits
        // (From MSB and including MSB)
        // are set. It does following
        // 110011001 | 001100110 = 111111111
        size |= size >> 2;

        size |= size >> 4;
        size |= size >> 8;
        size |= size >> 16;
        size |= size >> 32;

        // Increment sizeby 1 so that
        // there is only one set bit
        // which is just before original
        // MSB. sizenow becomes 1000000000
        size = size + 1;

        // Retursizeoriginal MSB after shifting.
        // sizenow becomes 100000000
        return (size >> 1);
    }

    public static int msb(int size) {
        // Below steps set bits after
        // MSB (including MSB)

        // Suppose sizeis 273 (binary
        // is 100010001). It does following
        // 100010001 | 010001000 = 110011001
        size |= size >> 1;

        // This makes sure 4 bits
        // (From MSB and including MSB)
        // are set. It does following
        // 110011001 | 001100110 = 111111111
        size |= size >> 2;

        size |= size >> 4;
        size |= size >> 8;
        size |= size >> 16;

        // Increment sizeby 1 so that
        // there is only one set bit
        // which is just before original
        // MSB. sizenow becomes 1000000000
        size = size + 1;

        // Retursizeoriginal MSB after shifting.
        // sizenow becomes 100000000
        return (size >> 1);
    }

    public long getTreeSize() {
        return treeSize;
    }

    public long getTargetNode() {
        return targetNode;
    }

    public BitNavigator navigateTo(final long node) {
        targetNode = node;
        currentMask = msb(targetNode);

        return this;
    }

    public BitNavigator insertion() {
        targetNode = (treeSize / 2) + 1;
        currentMask = msb(targetNode);

        return this;
    }

    public BitNavigator rightMostLeaf() {
        long delta = treeSize - (treeSize / 2);
        long odd = ((delta & 1L) == 1L) ? 1 : 0;
        delta = ((delta & 1L) == 1L) ? 0 : 1;

        currentMask = msb(treeSize + delta) - 1;
        targetNode = currentMask;

        return this;
    }

    public NavigationStep nextStep() {
        currentMask = currentMask >>> 1;

        if (currentMask == 0) {
            return NavigationStep.COMPLETE;
        }

        if ((targetNode & currentMask) == currentMask) {
            return NavigationStep.RIGHT;
        }

        return NavigationStep.LEFT;
    }
}
