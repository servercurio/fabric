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
import com.servercurio.fabric.core.security.HashAlgorithm;
import com.servercurio.fabric.core.security.MockHash;
import com.servercurio.fabric.core.security.impl.DefaultCryptographyImpl;
import com.servercurio.fabric.core.serialization.MockObjectSerializer;
import com.servercurio.fabric.core.serialization.MockSerializable;
import com.servercurio.fabric.core.serialization.Version;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Collections: MerkleTree")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class MerkleTreeTests {

    private static final MockHash WELL_KNOWN_HASH;
    private static final MockHash ALTERNATE_WELL_KNOWN_HASH;
    private static MockObjectSerializer objectSerializer;


    static {
        WELL_KNOWN_HASH = new MockHash(HashAlgorithm.SHA_384,
                                       Base64.getDecoder()
                                             .decode("pKA/NF3xZhm+DOBne5MhXxq41eSYHyom/bAPvyCrrDNT8vt5eODhhtWG7LpQlHEE"));

        ALTERNATE_WELL_KNOWN_HASH = new MockHash(HashAlgorithm.SHA_384,
                                                 Base64.getDecoder()
                                                       .decode("RXzuRQUHOT5zssgipY+PLujP4FrmQJQzVAvni+s52GcwtzkAnq+nRwwmW7noRqvx"));

        objectSerializer = new MockObjectSerializer();
    }

    @BeforeAll
    public static void startup() {

    }

    @AfterAll
    public static void shutdown() {

    }

    @ParameterizedTest
    @Order(100)
    @DisplayName("Correctness :: Insert -> Validate Exists")
    @ValueSource(ints = {1, 2, 6, 10})
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
    @ValueSource(ints = {1, 2, 6, 10})
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

    @Test
    @Order(300)
    @DisplayName("Correctness :: Iterator -> Empty Next")
    public void testCorrectnessIteratorEmptyNext() {
        final MerkleTree<MockSerializable> tree = new MerkleTree<>();

        assertEquals(0, tree.size());
        assertEquals(1, tree.getNodeCount());

        final Iterator<MockSerializable> iterator = tree.iterator();

        assertThrows(NoSuchElementException.class, iterator::next);
    }

    @Test
    @Order(301)
    @DisplayName("Correctness :: Iterator -> Empty Remove")
    public void testCorrectnessIteratorEmptyRemove() {
        final MerkleTree<MockSerializable> tree = new MerkleTree<>();

        assertEquals(0, tree.size());
        assertEquals(1, tree.getNodeCount());

        final Iterator<MockSerializable> iterator = tree.iterator();

        assertThrows(IllegalStateException.class, iterator::remove);
    }

    @ParameterizedTest
    @Order(302)
    @DisplayName("Correctness :: Iterator -> Comodification")
    @ValueSource(ints = {3})
    public void testCorrectnessIteratorComodification(int seedCount) throws InterruptedException {
        final MerkleTree<MockSerializable> tree = new MerkleTree<>();

        for (int i = 0; i < seedCount; i++) {
            tree.add(new MockSerializable(i));
        }

        assertEquals(seedCount, tree.size());
        assertEquals(((seedCount * 2) - 1), tree.getNodeCount());

        final AtomicInteger exceptionCount = new AtomicInteger(0);
        final Runnable runnable = () -> {
            try {
                for (int i = 0; i < seedCount * 2; i++) {
                    final int startSize = tree.size();
                    for (int j = 0; j < seedCount * 2; j++) {
                        tree.add(new MockSerializable(startSize + j));
                    }

                    tree.remove(new MockSerializable(tree.size() - 1));
                }
            } catch (ConcurrentModificationException ex) {
                exceptionCount.incrementAndGet();
            }
        };

        final Thread adderThread = new Thread(runnable);
        final Thread doubleAdderThread = new Thread(runnable);

        adderThread.start();
        doubleAdderThread.start();
        Thread.sleep(1);
        final Iterator<MockSerializable> iterator = tree.iterator();

        for (int i = 0; i < seedCount * 2; i++) {
            try {
                while (iterator.hasNext()) {
                    iterator.next();
                }
            } catch (ConcurrentModificationException ex) {
                exceptionCount.incrementAndGet();
            }
        }

        adderThread.join();
        doubleAdderThread.join();

        assertTrue(exceptionCount.get() >= 1);
    }

    @Test
    @Order(400)
    @DisplayName("Correctness :: Constructor -> Exceptions")
    public void testCorrectnessConstructorExceptions() {
        assertThrows(IllegalArgumentException.class, () -> new MerkleTree<MockSerializable>((HashAlgorithm) null));
        assertThrows(IllegalArgumentException.class, () -> new MerkleTree<MockSerializable>(HashAlgorithm.NONE));

        assertThrows(IllegalArgumentException.class,
                     () -> new MerkleTree<MockSerializable>(HashAlgorithm.SHA_384, null));

        assertThrows(IllegalArgumentException.class, () -> new MerkleTree<MockSerializable>(null, HashAlgorithm.SHA_384,
                                                                                            DefaultCryptographyImpl
                                                                                                    .getInstance()));

        assertThrows(IllegalArgumentException.class, () -> new MerkleTree<>((Collection<MockSerializable>) null));
        assertThrows(IllegalArgumentException.class, () -> new MerkleTree<>(new LinkedList<>(), HashAlgorithm.NONE));
        assertThrows(IllegalArgumentException.class, () -> new MerkleTree<>(null, HashAlgorithm.SHA_384));

        assertDoesNotThrow(() -> new MerkleTree<MockSerializable>(new LinkedList<>(), HashAlgorithm.SHA_384,
                                                                  DefaultCryptographyImpl.getInstance()));
        assertDoesNotThrow(() -> new MerkleTree<MockSerializable>(new LinkedList<>(), HashAlgorithm.SHA_384));
        assertDoesNotThrow(() -> new MerkleTree<MockSerializable>(new LinkedList<>()));
    }

    @Test
    @Order(500)
    @DisplayName("Serialization :: Recover -> Small Tree")
    public void testSerializationRecoverSmallTree() throws IOException {
        final MerkleTree<Hash> tree = new MerkleTree<>();

        assertEquals(0, tree.size());
        assertEquals(1, tree.getNodeCount());

        tree.add(WELL_KNOWN_HASH);
        tree.add(ALTERNATE_WELL_KNOWN_HASH);

        assertEquals(2, tree.size());
        assertEquals(3, tree.getNodeCount());

        byte[] serializedTree = null;

        try (final ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            try (final DataOutputStream dos = new DataOutputStream(bos)) {

                objectSerializer.serialize(dos, tree);
                dos.flush();
                bos.flush();

                serializedTree = bos.toByteArray();
            }
        }

        assertNotNull(serializedTree);
        assertTrue(serializedTree.length > 1);

        MerkleTree<Hash> recoveredTree = null;

        try (final ByteArrayInputStream bis = new ByteArrayInputStream(serializedTree)) {
            try (final DataInputStream dis = new DataInputStream(bis)) {
                recoveredTree = objectSerializer.deserialize(dis);
            }
        }

        assertNotNull(recoveredTree);
        assertEquals(2, recoveredTree.size());
        assertEquals(3, recoveredTree.getNodeCount());
        assertEquals(tree.getHash(), recoveredTree.getHash());
    }

    @Test
    @Order(501)
    @DisplayName("Serialization :: New Instance -> Throws")
    public void testSerializationNewInstanceThrows() {
        assertThrows(UnsupportedOperationException.class,
                     () -> objectSerializer.newInstance(MerkleTree.OBJECT_ID, MerkleTree.VERSIONS.last()));
    }

    @Test
    @Order(600)
    @DisplayName("Serialization :: Version History -> Contains")
    public void testSerializationVersionHistoryContains() {
        final MerkleTree<MockSerializable> tree = new MerkleTree<>();
        final SortedSet<Version> treeVersions = tree.getVersionHistory();

        assertNotNull(treeVersions);
        assertFalse(treeVersions.isEmpty());
        assertEquals(1, treeVersions.size());
    }
}
