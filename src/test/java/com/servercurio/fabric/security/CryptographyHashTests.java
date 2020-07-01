/*
 * Copyright 2019-2020 Server Curio
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

package com.servercurio.fabric.security;

import com.servercurio.fabric.io.ThrowingInputStream;
import com.servercurio.fabric.lang.Constants;
import com.servercurio.fabric.security.impl.DefaultCryptographyImpl;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.*;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static com.servercurio.fabric.lang.Constants.Comparable.*;
import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Cryptography: Hashing")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class CryptographyHashTests {

    private static final MockHash WELL_KNOWN_HASH;
    private static final MockHash ALTERNATE_WELL_KNOWN_HASH;
    private static final MockHash HASH_OF_WELL_KNOWN_HASHES;
    private static final MockHash HASH_OF_NULL_LEFT_HASHES;
    private static final MockHash HASH_OF_NULL_RIGHT_HASHES;

    private static final String LARGE_FILE_NAME =
            "90bf0ba937946ceae52361d742eede93eee76cc502156d73e1bc8aadb7dd827437b80434f793cbe539ae1330d30fb12c.bin";
    private static final MockHash LARGE_FILE_KNOWN_HASH;

    private static final byte[] IN_MEMORY_DATA;
    private static final MockHash IN_MEMORY_DATA_KNOWN_HASH;

    static {
        WELL_KNOWN_HASH = new MockHash(HashAlgorithm.SHA_384,
                                       Base64.getDecoder()
                                             .decode("pKA/NF3xZhm+DOBne5MhXxq41eSYHyom/bAPvyCrrDNT8vt5eODhhtWG7LpQlHEE"));

        ALTERNATE_WELL_KNOWN_HASH = new MockHash(HashAlgorithm.SHA_384,
                                                 Base64.getDecoder()
                                                       .decode("RXzuRQUHOT5zssgipY+PLujP4FrmQJQzVAvni+s52GcwtzkAnq+nRwwmW7noRqvx"));

        HASH_OF_WELL_KNOWN_HASHES = new MockHash(HashAlgorithm.SHA_384,
                                                 Base64.getDecoder()
                                                       .decode("jJ2gb5dQn1Bxdz0fxLowPxakxynJFajOjm7PBbkIVuznXA/9Cfa4QlFAagSyvDTm"));

        HASH_OF_NULL_LEFT_HASHES = new MockHash(HashAlgorithm.SHA_384,
                                                Base64.getDecoder()
                                                      .decode("wWH+6wHMHWLaWd3Hi00x+igQ5ZX5IFQ2OAlEEhQZozUAoJZBIreDb0PZw+IQHXoS"));

        HASH_OF_NULL_RIGHT_HASHES = new MockHash(HashAlgorithm.SHA_384,
                                                 Base64.getDecoder()
                                                       .decode("szH3dRl7j8nnVla3HCtvC6eJqeB9aLa5ZZNH5KofMWJV/crbu5BCqvEsOWsSbSdq"));

        LARGE_FILE_KNOWN_HASH = new MockHash(HashAlgorithm.SHA_384,
                                             Base64.getDecoder()
                                                   .decode("iztga7XMnm5KBe5gkbsPu1XUGdQUGJNG4gC3zSQNtKWBQ78y/N6nm/jXHwSq563L"));

        IN_MEMORY_DATA = Base64.getDecoder()
                               .decode("3K0By4fDo8jHaEoYKK7vtyb5KE1t1uYKG5p+r5ZNcnvNYCYZSTgAB6PpvHmsSGTwWov+42iTjzg9Eu4DBHtAdw==");

        IN_MEMORY_DATA_KNOWN_HASH = new MockHash(HashAlgorithm.SHA_384,
                                                 Base64.getDecoder()
                                                       .decode("AhmB45prgDLfSo23+TqTa3U231O85iO424sEe+lgxVhPbyviG23klX+VRcNOAOMj"));
    }

    @AfterAll
    public static void shutdown() {

    }

    @BeforeAll
    public static void startup() {

    }

    @BeforeEach
    public void beforeTest() {
        WELL_KNOWN_HASH.setOverrideAlgorithm(null);
        ALTERNATE_WELL_KNOWN_HASH.setOverrideAlgorithm(null);
        HASH_OF_WELL_KNOWN_HASHES.setOverrideAlgorithm(null);
    }

    @Test
    @Order(103)
    @DisplayName("Hash :: SHA_384 -> Byte Buffer")
    public void testCryptoSha384ByteBuffer() throws NoSuchAlgorithmException {
        final Cryptography provider = Cryptography.getDefaultInstance();

        final ByteBuffer buffer = ByteBuffer.allocateDirect(IN_MEMORY_DATA.length);
        buffer.put(IN_MEMORY_DATA).rewind();

        final Hash defaultBufferHash = provider
                .digestSync(buffer);

        buffer.rewind();

        final Hash explicitBufferHash = provider
                .digestSync(buffer, HashAlgorithm.SHA_384);

        assertEquals(IN_MEMORY_DATA_KNOWN_HASH, defaultBufferHash);
        assertArrayEquals(IN_MEMORY_DATA_KNOWN_HASH.getValue(), defaultBufferHash.getValue());

        assertEquals(IN_MEMORY_DATA_KNOWN_HASH, explicitBufferHash);
        assertArrayEquals(IN_MEMORY_DATA_KNOWN_HASH.getValue(), explicitBufferHash.getValue());

        assertEquals(1, DefaultCryptographyImpl.getHashAlgorithmCache().get().size());

    }

    @Test
    @Order(25)
    @DisplayName("Hash :: HashAlgorithm -> Basic Enum")
    public void testCryptoHashAlgorithmBasicEnum() throws Exception {
        assertEquals(384, HashAlgorithm.SHA_384.bits());
        assertEquals(48, HashAlgorithm.SHA_384.bytes());
        assertEquals(HashAlgorithm.SHA_384, HashAlgorithm.valueOf("SHA_384"));
        assertEquals(HashAlgorithm.SHA_384, HashAlgorithm.valueOf(HashAlgorithm.SHA_384.id()));
        assertEquals("SHA-384", HashAlgorithm.SHA_384.algorithmName());

        assertNull(HashAlgorithm.valueOf(-1));

        assertThrows(CryptographyException.class, HashAlgorithm.NONE::instance);
        assertThrows(CryptographyException.class, () -> HashAlgorithm.NONE.instance(new BouncyCastleProvider()));
        assertThrows(CryptographyException.class, () -> HashAlgorithm.SHA_384.instance("INVALID"));
    }

    @Test
    @Order(50)
    @DisplayName("Hash :: SHA_384 -> Basic Hash")
    public void testCryptoSha384BasicHash() throws Exception {
        try (final Cryptography provider = Cryptography.newDefaultInstance()) {

            final byte[] invalidLengthHash = new byte[HashAlgorithm.SHA_384.bytes() - 5];

            assertThrows(IllegalArgumentException.class, () -> new Hash(null, WELL_KNOWN_HASH.getValue()));
            assertThrows(IllegalArgumentException.class, () -> new Hash(HashAlgorithm.SHA_384, null));
            assertThrows(IllegalArgumentException.class, () -> new Hash(HashAlgorithm.SHA_384, invalidLengthHash));

            assertThrows(IllegalArgumentException.class, () -> new Hash(null));

            final Hash emptyCopy = new Hash(Hash.EMPTY);
            final Hash validCopy = new Hash(WELL_KNOWN_HASH);

            assertTrue(emptyCopy.isEmpty());
            assertFalse(validCopy.isEmpty());

            assertEquals(Hash.EMPTY, Hash.EMPTY);
            assertNotEquals(Hash.EMPTY, null);

            assertEquals(EQUALS, Hash.EMPTY.compareTo(emptyCopy));
            assertEquals(EQUALS, Hash.EMPTY.compareTo(Hash.EMPTY));
            assertEquals(GREATER_THAN, Hash.EMPTY.compareTo(null));

            assertEquals("a4a03f34", WELL_KNOWN_HASH.getPrefix());
            assertEquals("a4a03f345df1", WELL_KNOWN_HASH.getPrefix(6));
            assertThrows(IndexOutOfBoundsException.class, Hash.EMPTY::getPrefix);

            assertNotNull(Hash.EMPTY.toString());
            assertTrue(validCopy.hashCode() != 0);

            assertEquals(Hash.EMPTY, emptyCopy);
            assertEquals(WELL_KNOWN_HASH, validCopy);

            assertThrows(IllegalArgumentException.class, () -> emptyCopy.setAlgorithm(null));

            emptyCopy.setAlgorithm(HashAlgorithm.SHA_384);
            assertEquals(HashAlgorithm.SHA_384.bytes(), emptyCopy.getValue().length);

            assertThrows(IllegalArgumentException.class, () -> validCopy.setValue(null));
            assertThrows(IllegalArgumentException.class, () -> validCopy.setValue(invalidLengthHash));

            validCopy.setValue(new byte[HashAlgorithm.SHA_384.bytes()]);
            assertTrue(validCopy.isEmpty());
        }
    }

    @Test
    @Order(100)
    @DisplayName("Hash :: SHA_384 -> Hash of Hashes")
    public void testCryptoSha384HashOfHashes() throws Exception {
        try (final Cryptography provider = Cryptography.newDefaultInstance()) {

            final Hash defaultHashOfHashes = provider
                    .digestSync(WELL_KNOWN_HASH, ALTERNATE_WELL_KNOWN_HASH);

            final Hash explicitHashOfHashes = provider
                    .digestSync(WELL_KNOWN_HASH, ALTERNATE_WELL_KNOWN_HASH, HashAlgorithm.SHA_384);

            final Hash nullLeftHashOfHashes = provider.digestSync(null, ALTERNATE_WELL_KNOWN_HASH);

            final Hash nullRightHashOfHashes = provider.digestSync(WELL_KNOWN_HASH, null);

            assertEquals(HASH_OF_WELL_KNOWN_HASHES, defaultHashOfHashes);
            assertArrayEquals(HASH_OF_WELL_KNOWN_HASHES.getValue(), defaultHashOfHashes.getValue());

            assertEquals(HASH_OF_WELL_KNOWN_HASHES, explicitHashOfHashes);
            assertArrayEquals(HASH_OF_WELL_KNOWN_HASHES.getValue(), explicitHashOfHashes.getValue());

            assertEquals(HASH_OF_NULL_LEFT_HASHES, nullLeftHashOfHashes);
            assertEquals(HASH_OF_NULL_RIGHT_HASHES, nullRightHashOfHashes);

            assertEquals(1, DefaultCryptographyImpl.getHashAlgorithmCache().get().size());
        }
    }

    @Test
    @Order(102)
    @DisplayName("Hash :: SHA_384 -> In Memory Data")
    public void testCryptoSha384InMemoryData() throws NoSuchAlgorithmException {
        final Cryptography provider = Cryptography.getDefaultInstance();

        final Hash defaultMemoryDataHash = provider.digestSync(IN_MEMORY_DATA);

        final Hash explicitMemoryDataHash = provider
                .digestSync(IN_MEMORY_DATA, HashAlgorithm.SHA_384);


        assertEquals(IN_MEMORY_DATA_KNOWN_HASH, defaultMemoryDataHash);
        assertArrayEquals(IN_MEMORY_DATA_KNOWN_HASH.getValue(), defaultMemoryDataHash.getValue());

        assertEquals(IN_MEMORY_DATA_KNOWN_HASH, explicitMemoryDataHash);
        assertArrayEquals(IN_MEMORY_DATA_KNOWN_HASH.getValue(), explicitMemoryDataHash.getValue());

        assertEquals(1, DefaultCryptographyImpl.getHashAlgorithmCache().get().size());

    }

    @Test
    @Order(101)
    @DisplayName("Hash :: SHA_384 -> Large File")
    public void testCryptoSha384LargeFile() throws NoSuchAlgorithmException, IOException {
        final Cryptography provider = Cryptography.getDefaultInstance();
        final ClassLoader classLoader = getClass().getClassLoader();

        try (final InputStream stream = classLoader.getResourceAsStream(LARGE_FILE_NAME)) {
            final Hash defaultFileHash = provider.digestSync(stream);

            assertNotNull(defaultFileHash);
            assertEquals(LARGE_FILE_KNOWN_HASH, defaultFileHash);
            assertArrayEquals(LARGE_FILE_KNOWN_HASH.getValue(), defaultFileHash.getValue());
        }

        try (final InputStream stream = classLoader.getResourceAsStream(LARGE_FILE_NAME)) {
            final Hash explicitFileHash = provider.digestSync(stream, HashAlgorithm.SHA_384);

            assertNotNull(explicitFileHash);
            assertEquals(LARGE_FILE_KNOWN_HASH, explicitFileHash);
            assertArrayEquals(LARGE_FILE_KNOWN_HASH.getValue(), explicitFileHash.getValue());
        }

        assertThrows(CryptographyException.class, () -> {
            try (
                    final InputStream stream = classLoader.getResourceAsStream(LARGE_FILE_NAME);
                    final ThrowingInputStream throwingStream = new ThrowingInputStream(stream)
            ) {
                final Hash explicitFileHash = provider.digestSync(throwingStream, HashAlgorithm.SHA_384);

                assertNotNull(explicitFileHash);
                assertEquals(LARGE_FILE_KNOWN_HASH, explicitFileHash);
                assertArrayEquals(LARGE_FILE_KNOWN_HASH.getValue(), explicitFileHash.getValue());
            }
        });

        assertEquals(1, DefaultCryptographyImpl.getHashAlgorithmCache().get().size());

    }
}
