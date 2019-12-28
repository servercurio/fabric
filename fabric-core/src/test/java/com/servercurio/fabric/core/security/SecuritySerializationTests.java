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

package com.servercurio.fabric.core.security;

import com.servercurio.fabric.core.io.BadIOException;
import com.servercurio.fabric.core.security.spi.SecuritySerializationProvider;
import com.servercurio.fabric.core.serialization.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.*;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Serialization: Security")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class SecuritySerializationTests {

    private static final MockHash WELL_KNOWN_HASH;
    private static final MockHash ALTERNATE_WELL_KNOWN_HASH;
    private static final byte[] SERIALIZED_WELL_KNOWN_HASH;
    private static final byte[] SERIALIZED_HASH_INVALID_VERSION;
    private static final byte[] SERIALIZED_HASH_INVALID_ALGORITHM;
    private static MockObjectSerializer objectSerializer;

    static {
        WELL_KNOWN_HASH = new MockHash(HashAlgorithm.SHA_384,
                Base64.getDecoder().decode("pKA/NF3xZhm+DOBne5MhXxq41eSYHyom/bAPvyCrrDNT8vt5eODhhtWG7LpQlHEE"));

        ALTERNATE_WELL_KNOWN_HASH = new MockHash(HashAlgorithm.SHA_384,
                Base64.getDecoder().decode("RXzuRQUHOT5zssgipY+PLujP4FrmQJQzVAvni+s52GcwtzkAnq+nRwwmW7noRqvx"));

        SERIALIZED_WELL_KNOWN_HASH = WELL_KNOWN_HASH.toByteArray();

        WELL_KNOWN_HASH.setOverrideVersion(new Version(0, 0, 0));
        SERIALIZED_HASH_INVALID_VERSION = WELL_KNOWN_HASH.toByteArray();
        WELL_KNOWN_HASH.setOverrideVersion(null);

        WELL_KNOWN_HASH.setOverrideAlgorithm(HashAlgorithm.NONE);
        SERIALIZED_HASH_INVALID_ALGORITHM = WELL_KNOWN_HASH.toByteArray();
        WELL_KNOWN_HASH.setOverrideAlgorithm(null);

    }

    @BeforeAll
    public static void startup() {
        objectSerializer = new MockObjectSerializer();
    }

    @AfterAll
    public static void shutdown() {

    }

    @BeforeEach
    public void beforeTest() {
        WELL_KNOWN_HASH.setOverrideObjectId(null);
        WELL_KNOWN_HASH.setOverrideAlgorithm(null);
        WELL_KNOWN_HASH.setOverrideVersion(null);
    }

    @Test
    @Order(100)
    @DisplayName("Provider :: Initialize")
    public void testProviderInitialize() {
        assertDoesNotThrow(() -> assertTrue(objectSerializer.checkProvider(Hash.OBJECT_ID, Hash.VERSIONS.last())));
    }

    @Test
    @Order(200)
    @DisplayName("Provider :: New Instance -> Known Identifier")
    public void testProviderKnownIdNewInstance() {
        assertDoesNotThrow(() -> {
            final Hash emptyHash = objectSerializer.newInstance(Hash.OBJECT_ID, Hash.VERSIONS.last());
            assertNotNull(emptyHash);
        });
    }

    @Test
    @Order(201)
    @DisplayName("Provider :: New Instance -> Unknown Identifier")
    public void testProviderUnknownIdNewInstance() {
        assertDoesNotThrow(() -> {
            final Hash emptyHash = objectSerializer
                    .newInstance(new SecuritySerializationProvider(), new ObjectId(0, 0), Hash.VERSIONS.last());
            assertNull(emptyHash);
        });
    }

    @Test
    @Order(202)
    @DisplayName("Provider :: New Instance -> Unknown Version")
    public void testProviderUnknownVersionNewInstance() {
        assertDoesNotThrow(() -> {
            final Hash emptyHash = objectSerializer
                    .newInstance(new SecuritySerializationProvider(), Hash.OBJECT_ID, new Version(0, 0, 0));
            assertNull(emptyHash);
        });
    }

    @Test
    @Order(400)
    @DisplayName("Hash :: Serialize -> Well Known")
    public void testHashWellKnownSerialization() throws IOException {

        byte[] serializedHash = null;

        try (final ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            try (final DataOutputStream dos = new DataOutputStream(bos)) {
                objectSerializer.serialize(dos, WELL_KNOWN_HASH);
                dos.flush();
                bos.flush();

                serializedHash = bos.toByteArray();
            }
        }

        assertNotNull(serializedHash);
        assertArrayEquals(SERIALIZED_WELL_KNOWN_HASH, serializedHash);

        try (final ByteArrayInputStream bis = new ByteArrayInputStream(serializedHash)) {
            try (final DataInputStream dis = new DataInputStream(bis)) {
                final Hash recoveredHash = objectSerializer.deserialize(dis);
                assertNotNull(recoveredHash);
                assertEquals(WELL_KNOWN_HASH, recoveredHash);
            }
        }
    }

    @Test
    @Order(401)
    @DisplayName("Hash :: Serialize -> Unknown Identifier")
    public void testHashSerializeUnknownIdentifier() throws IOException {

        try (final ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            try (final DataOutputStream dos = new DataOutputStream(bos)) {
                WELL_KNOWN_HASH.setOverrideObjectId(new ObjectId(0, 0));
                assertThrows(ObjectNotSerializableException.class,
                        () -> objectSerializer.serialize(dos, WELL_KNOWN_HASH));
                dos.flush();
                bos.flush();

            }
        }

    }

    @Test
    @Order(402)
    @DisplayName("Hash :: Serialize -> Unknown Version")
    public void testHashSerializeUnknownVersion() throws IOException {

        try (final ByteArrayInputStream bis = new ByteArrayInputStream(SERIALIZED_HASH_INVALID_VERSION)) {
            try (final DataInputStream dis = new DataInputStream(bis)) {
                final Hash recoveredHash = objectSerializer.deserialize(new SecuritySerializationProvider(), dis);
                assertNull(recoveredHash);
            }
        }

    }

    @Test
    @Order(403)
    @DisplayName("Hash :: Serialize -> Unknown Algorithm")
    public void testHashSerializeUnknownAlgorithm() throws IOException {

        try (final ByteArrayInputStream bis = new ByteArrayInputStream(SERIALIZED_HASH_INVALID_ALGORITHM)) {
            try (final DataInputStream dis = new DataInputStream(bis)) {
                assertThrows(BadIOException.class,
                        () -> objectSerializer.deserialize(new SecuritySerializationProvider(), dis));
            }
        }

    }

    @Test
    @Order(500)
    @DisplayName("Hash :: Object -> Equals")
    public void testHashObjectEquals() {
        final MockHash initialHash = new MockHash(WELL_KNOWN_HASH);
        final MockHash sameHash = new MockHash(WELL_KNOWN_HASH);
        final MockHash nextHash = new MockHash(ALTERNATE_WELL_KNOWN_HASH);

        assertEquals(initialHash, sameHash);
        assertNotEquals(initialHash, nextHash);
        assertNotEquals(sameHash, nextHash);

        assertEquals(initialHash, initialHash);
        assertNotEquals(initialHash, new MockSerializable());
    }

    @Test
    @Order(501)
    @DisplayName("Hash :: Object -> Hash Code")
    public void testHashObjectHashCode() {
        final MockHash initialHash = new MockHash(WELL_KNOWN_HASH);
        final MockHash sameHash = new MockHash(WELL_KNOWN_HASH);
        final MockHash nextHash = new MockHash(ALTERNATE_WELL_KNOWN_HASH);

        assertEquals(initialHash.hashCode(), sameHash.hashCode());
        assertNotEquals(initialHash.hashCode(), nextHash.hashCode());
        assertNotEquals(sameHash.hashCode(), nextHash.hashCode());
    }

    @Test
    @Order(502)
    @DisplayName("Hash :: Object -> Comparable")
    public void testHashObjectComparable() {
        final MockHash initialHash = new MockHash(WELL_KNOWN_HASH);
        final MockHash sameHash = new MockHash(WELL_KNOWN_HASH);
        final MockHash nextHash = new MockHash(ALTERNATE_WELL_KNOWN_HASH);

        assertEquals(0, initialHash.compareTo(sameHash));
        assertEquals(0, sameHash.compareTo(initialHash));
        assertNotEquals(0, initialHash.compareTo(nextHash));
        assertNotEquals(0, sameHash.compareTo(nextHash));

        assertEquals(1, initialHash.compareTo(null));
    }

    @Test
    @Order(503)
    @DisplayName("Hash :: Object -> To String")
    public void testHashObjectToString() {
        final MockHash initialHash = new MockHash(WELL_KNOWN_HASH);
        final MockHash sameHash = new MockHash(WELL_KNOWN_HASH);
        final MockHash nextHash = new MockHash(ALTERNATE_WELL_KNOWN_HASH);

        assertEquals(initialHash.toString(), sameHash.toString());
        assertNotEquals(initialHash.toString(), nextHash.toString());
        assertNotEquals(sameHash.toString(), nextHash.toString());

        assertEquals(
                "{\"algorithm\":\"SHA_384\",\"value\":\"pKA\\/NF3xZhm+DOBne5MhXxq41eSYHyom\\/bAPvyCrrDNT8vt5eODhhtWG7LpQlHEE\"}",
                initialHash.toString());
        assertEquals(
                "{\"algorithm\":\"SHA_384\",\"value\":\"pKA\\/NF3xZhm+DOBne5MhXxq41eSYHyom\\/bAPvyCrrDNT8vt5eODhhtWG7LpQlHEE\"}",
                sameHash.toString());
        assertEquals(
                "{\"algorithm\":\"SHA_384\",\"value\":\"RXzuRQUHOT5zssgipY+PLujP4FrmQJQzVAvni+s52GcwtzkAnq+nRwwmW7noRqvx\"}",
                nextHash.toString());
    }

    @Test
    @Order(504)
    @DisplayName("Hash :: Object -> Constructors")
    public void testHashObjectConstructors() {
        assertThrows(IllegalArgumentException.class, () -> new Hash(null, WELL_KNOWN_HASH.getValue()));
        assertThrows(IllegalArgumentException.class, () -> new Hash(HashAlgorithm.SHA_384, null));
        assertThrows(IllegalArgumentException.class, () -> new Hash(null));
    }

    @Test
    @Order(505)
    @DisplayName("Hash :: Object -> Accessors")
    public void testHashObjectAccessors() {
        final MockHash zeroHash = new MockHash(HashAlgorithm.SHA_384, new byte[48]);
        final MockHash clonedHash = new MockHash(WELL_KNOWN_HASH);
        final MockHash mutatedHash = new MockHash(WELL_KNOWN_HASH);

        assertTrue(Hash.EMPTY.isEmpty());
        assertTrue(zeroHash.isEmpty());
        assertFalse(clonedHash.isEmpty());

        assertArrayEquals(clonedHash.getValue(), mutatedHash.getValue());
        assertThrows(IllegalArgumentException.class, () -> mutatedHash.setValue(null));
        assertThrows(IllegalArgumentException.class, () -> mutatedHash.setValue(new byte[5]));
        assertArrayEquals(clonedHash.getValue(), mutatedHash.getValue());

        assertEquals(clonedHash.getAlgorithm(), mutatedHash.getAlgorithm());
        assertThrows(IllegalArgumentException.class, () -> mutatedHash.setAlgorithm(null));
        assertEquals(clonedHash.getAlgorithm(), mutatedHash.getAlgorithm());

        mutatedHash.setAlgorithm(HashAlgorithm.SHA_256);
        assertEquals(HashAlgorithm.SHA_256, mutatedHash.getAlgorithm());
        assertNotEquals(clonedHash.getAlgorithm(), mutatedHash.getAlgorithm());

        mutatedHash.setAlgorithm(HashAlgorithm.SHA_384);
        mutatedHash.setValue(ALTERNATE_WELL_KNOWN_HASH.getValue());

        assertArrayEquals(ALTERNATE_WELL_KNOWN_HASH.getValue(), mutatedHash.getValue());


        assertNotNull(clonedHash.getObjectId());
        assertEquals(Hash.OBJECT_ID, clonedHash.getObjectId());

        assertNotNull(clonedHash.getVersion());
        assertEquals(Hash.VERSIONS.last(), clonedHash.getVersion());

        assertNotNull(clonedHash.getVersionHistory());
        assertTrue(clonedHash.getVersionHistory().size() > 0);
        assertEquals(clonedHash.getVersion(), clonedHash.getVersionHistory().last());
    }

    @Test
    @Order(600)
    @DisplayName("HashAlgorithm :: Enum -> Accessors")
    public void testHashAlgorithmEnumAccessors() throws NoSuchAlgorithmException, NoSuchProviderException {
        assertEquals(384, HashAlgorithm.SHA_384.bits());
        assertEquals(48, HashAlgorithm.SHA_384.bytes());

        MessageDigest digest = HashAlgorithm.SHA_384.instance();
        assertNotNull(digest);

        digest = HashAlgorithm.SHA_384.instance("SUN");
        assertNotNull(digest);

        digest = HashAlgorithm.SHA_384.instance(new BouncyCastleProvider());
        assertNotNull(digest);

        assertEquals(digest.getAlgorithm(), HashAlgorithm.SHA_384.algorithmName());
    }
}
