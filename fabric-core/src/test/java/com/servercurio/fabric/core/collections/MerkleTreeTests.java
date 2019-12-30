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

import com.servercurio.fabric.core.serialization.MockSerializable;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static com.servercurio.fabric.core.collections.BitNavigator.msb;
import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Collections: MerkleTree")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class MerkleTreeTests {

    @BeforeAll
    public static void startup() {

    }

    @AfterAll
    public static void shutdown() {

    }

    @ParameterizedTest
    @Order(100)
    @DisplayName("Correctness :: Insert -> Validate Exists")
    @ValueSource(ints = { 1, 2, 6, 10 })
    public void testCorrectnessInsertValidateExists(int numberOfElements) {
        final MerkleTree<MockSerializable> tree = new MerkleTree<>();
        final MockSerializable[] elements = new MockSerializable[numberOfElements];

        for (int i = 0; i < elements.length; i++) {
            elements[i] = new MockSerializable(i);
            tree.add(elements[i]);
        }

        assertEquals(numberOfElements, tree.size());

        for (MockSerializable item : elements) {
            assertTrue(tree.contains(item));
        }

        int expectedNodeCount = (numberOfElements * 2) - 1;
        if (numberOfElements < 2) {
            expectedNodeCount = (numberOfElements * 2);
        }

        System.out.println(String.format("Merkle Tree Hash: %s", tree.getHash()));
        assertEquals(expectedNodeCount, tree.getNodeCount());

    }

    @ParameterizedTest
    @Order(200)
    @DisplayName("Correctness :: Remove -> Validate Forward")
    @ValueSource(ints = { 1, 2, 6, 10 })
    public void testCorrectnessRemoveValidateForward(int numberOfElements) {
        final MerkleTree<MockSerializable> tree = new MerkleTree<>();
        final MockSerializable[] elements = new MockSerializable[numberOfElements];

        for (int i = 0; i < elements.length; i++) {
            elements[i] = new MockSerializable(i);
            tree.add(elements[i]);
        }

        assertEquals(numberOfElements, tree.size());

        for (MockSerializable item : elements) {
            assertTrue(tree.contains(item));
        }

        int expectedNodeCount = (numberOfElements * 2) - 1;
        if (numberOfElements < 2) {
            expectedNodeCount = (numberOfElements * 2);
        }

        assertEquals(expectedNodeCount, tree.getNodeCount());

        for (int i = 0; i < elements.length; i++) {

            tree.remove(elements[i]);
            assertEquals(numberOfElements - (i + 1), tree.size());
            assertFalse(tree.contains(elements[i]));

            for (int j = i + 1; j < elements.length; j++) {
                assertTrue(tree.contains(elements[j]));
            }
        }

        assertEquals(0, tree.size());
        assertEquals(1, tree.getNodeCount());
    }

}
