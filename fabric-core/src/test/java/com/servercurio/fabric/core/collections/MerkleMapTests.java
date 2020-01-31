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
import com.servercurio.fabric.core.security.impl.DefaultCryptographyImpl;
import com.servercurio.fabric.core.serialization.MockObjectSerializer;
import com.servercurio.fabric.core.serialization.SerializableString;
import com.servercurio.fabric.core.serialization.Version;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.*;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Collections: MerkleMap")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class MerkleMapTests {


    private static final MockObjectSerializer objectSerializer;

    private static final int NUMBER_OF_PAIRS = 100;
    private static final SerializableString[] generatedKeys = new SerializableString[NUMBER_OF_PAIRS];
    private static final SerializableString[] generatedValues = new SerializableString[NUMBER_OF_PAIRS];


    static {
        objectSerializer = new MockObjectSerializer();
    }

    @BeforeAll
    public static void startup() {
        assertEquals(NUMBER_OF_PAIRS, generatedKeys.length);
        assertEquals(NUMBER_OF_PAIRS, generatedValues.length);
        assertEquals(generatedKeys.length, generatedValues.length);

        for (int i = 0; i < generatedKeys.length; i++) {
            generatedKeys[i] = new SerializableString(String.format("key-%08d", i));
            generatedValues[i] = new SerializableString(String.format("value-%08d", i));
        }
    }

    @AfterAll
    public static void shutdown() {

    }

    @ParameterizedTest
    @Order(100)
    @DisplayName("Correctness :: Insert -> Validate Exists")
    @ValueSource(ints = {1, 2, 6, 10})
    public void testCorrectnessInsertValidateExists(int numberOfElements) {
        final MerkleMap<SerializableString, SerializableString> map = new MerkleMap<>();

        assertTrue(numberOfElements <= NUMBER_OF_PAIRS);

        for (int i = 0; i < numberOfElements; i++) {
            map.put(generatedKeys[i], generatedValues[i]);
        }

        assertEquals(numberOfElements, map.size());
        assertEquals(numberOfElements, map.getMerkleTree().size());

        for (int i = 0; i < numberOfElements; i++) {
            assertTrue(map.containsKey(generatedKeys[i]));
            assertTrue(map.containsValue(generatedValues[i]));

            assertEquals(generatedValues[i], map.get(generatedKeys[i]));
        }

        final Hash startingHash = map.getHash();

        map.clear();

        assertEquals(0, map.size());
        assertEquals(0, map.getMerkleTree().size());

        assertNotNull(map.getHash());
        assertNotEquals(startingHash, map.getHash());
    }

    @ParameterizedTest
    @Order(200)
    @DisplayName("Correctness :: Remove -> Validate Forward")
    @ValueSource(ints = {1, 2, 6, 10})
    public void testCorrectnessRemoveValidateForward(int numberOfElements) {
        final MerkleMap<SerializableString, SerializableString> map = new MerkleMap<>();

        assertTrue(numberOfElements <= NUMBER_OF_PAIRS);

        for (int i = 0; i < numberOfElements; i++) {
            map.put(generatedKeys[i], generatedValues[i]);
        }

        assertEquals(numberOfElements, map.size());
        assertEquals(numberOfElements, map.getMerkleTree().size());

        for (int i = 0; i < numberOfElements; i++) {
            assertTrue(map.containsKey(generatedKeys[i]));
            assertTrue(map.containsValue(generatedValues[i]));

            assertEquals(generatedValues[i], map.get(generatedKeys[i]));
        }


        for (int i = 0; i < numberOfElements; i++) {

            map.remove(generatedKeys[i]);
            assertEquals(numberOfElements - (i + 1), map.size());
            assertFalse(map.containsKey(generatedKeys[i]));

            for (int j = i + 1; j < numberOfElements; j++) {
                assertTrue(map.containsKey(generatedKeys[j]));
            }
        }

        assertEquals(0, map.size());
        assertEquals(0, map.getMerkleTree().size());
        assertEquals(1, map.getMerkleTree().getNodeCount());
    }

    @Test
    @Order(300)
    @DisplayName("Correctness :: Iterator -> Empty Next")
    public void testCorrectnessIteratorEmptyNext() {
        final MerkleMap<SerializableString, SerializableString> map = new MerkleMap<>();

        assertEquals(0, map.size());
        assertEquals(0, map.getMerkleTree().size());
        assertEquals(1, map.getMerkleTree().getNodeCount());

        final Iterator<Map.Entry<SerializableString, SerializableString>> iterator = map.entrySet().iterator();

        assertThrows(NoSuchElementException.class, iterator::next);
    }

    @Test
    @Order(301)
    @DisplayName("Correctness :: Iterator -> Empty Remove")
    public void testCorrectnessIteratorEmptyRemove() {
        final MerkleMap<SerializableString, SerializableString> map = new MerkleMap<>();

        assertEquals(0, map.size());
        assertEquals(0, map.getMerkleTree().size());
        assertEquals(1, map.getMerkleTree().getNodeCount());

        final Iterator<Map.Entry<SerializableString, SerializableString>> iterator = map.entrySet().iterator();

        assertThrows(IllegalStateException.class, iterator::remove);
    }

    //
//    @ParameterizedTest
//    @Order(302)
//    @DisplayName("Correctness :: Iterator -> Comodification")
//    @ValueSource(ints = {3})
//    public void testCorrectnessIteratorComodification(int seedCount) throws InterruptedException {
//        final MerkleTree<MockSerializable> tree = new MerkleTree<>();
//
//        for (int i = 0; i < seedCount; i++) {
//            tree.add(new MockSerializable(i));
//        }
//
//        assertEquals(seedCount, tree.size());
//        assertEquals(((seedCount * 2) - 1), tree.getNodeCount());
//
//        final AtomicInteger exceptionCount = new AtomicInteger(0);
//        final Runnable runnable = () -> {
//            try {
//                for (int i = 0; i < seedCount * 2; i++) {
//                    final int startSize = tree.size();
//                    for (int j = 0; j < seedCount * 2; j++) {
//                        tree.add(new MockSerializable(startSize + j));
//                    }
//
//                    tree.remove(new MockSerializable(tree.size() - 1));
//                }
//            } catch (ConcurrentModificationException ex) {
//                exceptionCount.incrementAndGet();
//            }
//        };
//
//        final Thread adderThread = new Thread(runnable);
//        final Thread doubleAdderThread = new Thread(runnable);
//
//        adderThread.start();
//        doubleAdderThread.start();
//        Thread.sleep(1);
//        final Iterator<MockSerializable> iterator = tree.iterator();
//
//        for (int i = 0; i < seedCount * 2; i++) {
//            try {
//                while (iterator.hasNext()) {
//                    iterator.next();
//                }
//            } catch (ConcurrentModificationException ex) {
//                exceptionCount.incrementAndGet();
//            }
//        }
//
//        adderThread.join();
//        doubleAdderThread.join();
//
//        assertTrue(exceptionCount.get() >= 1);
//    }
//
    @Test
    @Order(400)
    @DisplayName("Correctness :: Constructor -> Exceptions")
    public void testCorrectnessConstructorExceptions() {
        assertThrows(IllegalArgumentException.class,
                     () -> new MerkleMap<SerializableString, SerializableString>((HashAlgorithm) null));
        assertThrows(IllegalArgumentException.class,
                     () -> new MerkleMap<SerializableString, SerializableString>(HashAlgorithm.NONE));

        assertThrows(IllegalArgumentException.class,
                     () -> new MerkleMap<SerializableString, SerializableString>(HashAlgorithm.SHA_384, null));

        assertThrows(IllegalArgumentException.class,
                     () -> new MerkleMap<SerializableString, SerializableString>(null, HashAlgorithm.SHA_384,
                                                                                 DefaultCryptographyImpl
                                                                                         .getInstance()));

        assertThrows(IllegalArgumentException.class,
                     () -> new MerkleMap<>((Map<SerializableString, SerializableString>) null));
        assertThrows(IllegalArgumentException.class,
                     () -> new MerkleMap<SerializableString, SerializableString>(new HashMap<>(), HashAlgorithm.NONE));
        assertThrows(IllegalArgumentException.class, () -> new MerkleTree<>(null, HashAlgorithm.SHA_384));

        assertDoesNotThrow(
                () -> new MerkleMap<SerializableString, SerializableString>(new HashMap<>(), HashAlgorithm.SHA_384,
                                                                            DefaultCryptographyImpl.getInstance()));
        assertDoesNotThrow(
                () -> new MerkleMap<SerializableString, SerializableString>(new HashMap<>(), HashAlgorithm.SHA_384));
        assertDoesNotThrow(() -> new MerkleMap<SerializableString, SerializableString>(new HashMap<>()));
    }

    @ParameterizedTest
    @Order(500)
    @DisplayName("Serialization :: Recover -> Small Map")
    @ValueSource(ints = {1, 2, 6, 10})
    public void testSerializationRecoverSmallMap(int numberOfElements) throws IOException {
        final MerkleMap<SerializableString, SerializableString> map = new MerkleMap<>();

        assertEquals(0, map.size());
        assertEquals(0, map.getMerkleTree().size());
        assertEquals(1, map.getMerkleTree().getNodeCount());

        assertTrue(numberOfElements <= NUMBER_OF_PAIRS);

        for (int i = 0; i < numberOfElements; i++) {
            map.put(generatedKeys[i], generatedValues[i]);
        }

        assertEquals(numberOfElements, map.size());
        assertEquals(numberOfElements, map.getMerkleTree().size());


        byte[] serializedMap = null;

        try (final ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            try (final DataOutputStream dos = new DataOutputStream(bos)) {

                objectSerializer.serialize(dos, map);
                dos.flush();
                bos.flush();

                serializedMap = bos.toByteArray();
            }
        }

        assertNotNull(serializedMap);
        assertTrue(serializedMap.length > 1);

        MerkleMap<SerializableString, SerializableString> recoveredMap = null;

        try (final ByteArrayInputStream bis = new ByteArrayInputStream(serializedMap)) {
            try (final DataInputStream dis = new DataInputStream(bis)) {
                recoveredMap = objectSerializer.deserialize(dis);
            }
        }

        assertNotNull(recoveredMap);
        assertEquals(numberOfElements, recoveredMap.size());
        assertEquals(numberOfElements, recoveredMap.getMerkleTree().size());
        assertEquals((numberOfElements * 2) + 1, recoveredMap.getMerkleTree().getNodeCount());
        assertEquals(map.getHash(), recoveredMap.getHash());
    }

    @Test
    @Order(501)
    @DisplayName("Serialization :: New Instance -> Throws")
    public void testSerializationNewInstanceThrows() {
        assertThrows(UnsupportedOperationException.class,
                     () -> objectSerializer.newInstance(MerkleMap.OBJECT_ID, MerkleMap.VERSIONS.last()));
        assertThrows(UnsupportedOperationException.class,
                     () -> objectSerializer.newInstance(MerkleMapNode.OBJECT_ID, MerkleMapNode.VERSIONS.last()));
    }

    @Test
    @Order(600)
    @DisplayName("Serialization :: Version History -> Contains")
    public void testSerializationVersionHistoryContains() {
        final MerkleMap<SerializableString, SerializableString> map = new MerkleMap<>();
        final SortedSet<Version> mapVersions = map.getVersionHistory();

        assertNotNull(mapVersions);
        assertFalse(mapVersions.isEmpty());
        assertEquals(1, mapVersions.size());
    }
}
