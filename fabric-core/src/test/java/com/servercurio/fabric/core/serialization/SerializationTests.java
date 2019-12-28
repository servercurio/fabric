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

package com.servercurio.fabric.core.serialization;

import com.servercurio.fabric.core.security.Hash;
import org.junit.jupiter.api.*;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Serialization: API")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class SerializationTests {

    private static MockObjectSerializer objectSerializer;

    @BeforeAll
    public static void startup() {
        objectSerializer = new MockObjectSerializer();
    }

    @AfterAll
    public static void shutdown() {

    }

    @Test
    @Order(100)
    @DisplayName("Serializer :: Provider -> Known Identifier")
    public void testSerializerKnownObjectId() {
        assertDoesNotThrow(() -> assertTrue(objectSerializer.checkProvider(Hash.OBJECT_ID, Hash.VERSIONS.last())));
    }

    @Test
    @Order(101)
    @DisplayName("Serializer :: Provider -> Unknown Identifier")
    public void testSerializerUnknownObjectId() {
        assertThrows(UnknownObjectIdentifierException.class,
                () -> assertFalse(objectSerializer.checkProvider(new ObjectId(0, 0), new Version(0, 0, 0))));
    }

    @Test
    @Order(102)
    @DisplayName("Serializer :: Provider -> Unknown Version")
    public void testSerializerUnknownObjectVersion() {
        assertThrows(UnknownObjectIdentifierException.class,
                () -> assertTrue(objectSerializer.checkProvider(Hash.OBJECT_ID, new Version(0, 0, 0))));
    }

    @Test
    @Order(103)
    @DisplayName("Serializer :: Provider -> Unknown Object")
    public void testSerializerUnknownObject() throws IOException {
        try (final ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            try (final DataOutputStream dos = new DataOutputStream(bos)) {
                assertThrows(ObjectNotSerializableException.class,
                        () -> objectSerializer.serialize(dos, new MockSerializable()));
            }
        }
    }

    @Test
    @Order(200)
    @DisplayName("Serializer :: Persist -> Null Stream Argument")
    public void testSerializerPersistNullStream() throws IOException {
        assertThrows(IllegalArgumentException.class,
                () -> objectSerializer.serialize(null, new MockSerializable()));
    }

    @Test
    @Order(201)
    @DisplayName("Serializer :: Persist -> Null Object Argument")
    public void testSerializerPersistNullObject() throws IOException {
        try (final ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            try (final DataOutputStream dos = new DataOutputStream(bos)) {
                assertThrows(IllegalArgumentException.class,
                        () -> objectSerializer.serialize(dos, null));
            }
        }
    }

    @Test
    @Order(300)
    @DisplayName("Serializer :: Recover -> Null Stream Argument")
    public void testSerializerRecoverNullStream() throws IOException {
        assertThrows(IllegalArgumentException.class,
                () -> objectSerializer.deserialize(null));
    }

    @Test
    @Order(400)
    @DisplayName("Version :: Object -> Equals")
    public void testVersionObjectEquals() {
        final Version initialVersion = new Version(5, 9, 126);
        final Version sameVersion = new Version(5, 9, 126);
        final Version nextVersion = new Version(5, 9, 127);

        assertEquals(initialVersion, sameVersion);
        assertNotEquals(initialVersion, nextVersion);
        assertNotEquals(sameVersion, nextVersion);
    }

    @Test
    @Order(401)
    @DisplayName("Version :: Object -> Hash Code")
    public void testVersionObjectHashCode() {
        final Version initialVersion = new Version(5, 9, 126);
        final Version sameVersion = new Version(5, 9, 126);
        final Version nextVersion = new Version(5, 9, 127);

        assertEquals(initialVersion.hashCode(), sameVersion.hashCode());
        assertNotEquals(initialVersion.hashCode(), nextVersion.hashCode());
        assertNotEquals(sameVersion.hashCode(), nextVersion.hashCode());
    }

    @Test
    @Order(402)
    @DisplayName("Version :: Object -> To String")
    public void testVersionObjectToString() {
        final Version initialVersion = new Version(5, 9, 126);
        final Version sameVersion = new Version(5, 9, 126);
        final Version nextVersion = new Version(5, 9, 127);

        assertEquals(initialVersion.toString(), sameVersion.toString());
        assertNotEquals(initialVersion.toString(), nextVersion.toString());
        assertNotEquals(sameVersion.toString(), nextVersion.toString());

       assertEquals("{\"major\":5,\"minor\":9,\"revision\":126}", initialVersion.toString());
       assertEquals("{\"major\":5,\"minor\":9,\"revision\":126}", sameVersion.toString());
       assertEquals("{\"major\":5,\"minor\":9,\"revision\":127}", nextVersion.toString());
    }

    @Test
    @Order(500)
    @DisplayName("ObjectId :: Object -> Equals")
    public void testIdObjectEquals() {
        final ObjectId initialObjectId = new ObjectId(27, 1);
        final ObjectId sameObjectId = new ObjectId(27, 1);
        final ObjectId nextObjectId = new ObjectId(27, 2);

        assertEquals(initialObjectId, sameObjectId);
        assertNotEquals(initialObjectId, nextObjectId);
        assertNotEquals(sameObjectId, nextObjectId);
    }

    @Test
    @Order(501)
    @DisplayName("ObjectId :: Object -> Hash Code")
    public void testIdObjectHashCode() {
        final ObjectId initialObjectId = new ObjectId(27, 1);
        final ObjectId sameObjectId = new ObjectId(27, 1);
        final ObjectId nextObjectId = new ObjectId(27, 2);

        assertEquals(initialObjectId.hashCode(), sameObjectId.hashCode());
        assertNotEquals(initialObjectId.hashCode(), nextObjectId.hashCode());
        assertNotEquals(sameObjectId.hashCode(), nextObjectId.hashCode());
    }

    @Test
    @Order(502)
    @DisplayName("ObjectId :: Object -> Comparable")
    public void testIdObjectComparable() {
        final ObjectId initialObjectId = new ObjectId(27, 1);
        final ObjectId sameObjectId = new ObjectId(27, 1);
        final ObjectId nextObjectId = new ObjectId(27, 2);

        assertEquals(0, initialObjectId.compareTo(sameObjectId));
        assertEquals(0, sameObjectId.compareTo(initialObjectId));
        assertNotEquals(0, initialObjectId.compareTo(nextObjectId));
        assertNotEquals(0, sameObjectId.compareTo(nextObjectId));
    }

    @Test
    @Order(503)
    @DisplayName("ObjectId :: Object -> To String")
    public void testIdObjectToString() {
        final ObjectId initialObjectId = new ObjectId(27, 1);
        final ObjectId sameObjectId = new ObjectId(27, 1);
        final ObjectId nextObjectId = new ObjectId(27, 2);

        assertEquals(initialObjectId.toString(), sameObjectId.toString());
        assertNotEquals(initialObjectId.toString(), nextObjectId.toString());
        assertNotEquals(sameObjectId.toString(), nextObjectId.toString());

        assertEquals("{\"namespace\":27,\"identifier\":1}", initialObjectId.toString());
        assertEquals("{\"namespace\":27,\"identifier\":1}", sameObjectId.toString());
        assertEquals("{\"namespace\":27,\"identifier\":2}", nextObjectId.toString());
    }
}
