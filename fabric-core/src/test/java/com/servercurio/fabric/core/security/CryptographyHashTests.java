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

import com.servercurio.fabric.core.security.impl.DefaultCryptographyImpl;
import org.junit.jupiter.api.*;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Cryptography: Hashing")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class CryptographyHashTests {

    private static final MockHash WELL_KNOWN_HASH;
    private static final MockHash ALTERNATE_WELL_KNOWN_HASH;
    private static final MockHash HASH_OF_WELL_KNOWN_HASHES;

    private static final String LARGE_FILE_NAME = "90bf0ba937946ceae52361d742eede93eee76cc502156d73e1bc8aadb7dd827437b80434f793cbe539ae1330d30fb12c.bin";
    private static final MockHash LARGE_FILE_KNOWN_HASH;

    private static final byte[] IN_MEMORY_DATA;
    private static final MockHash IN_MEMORY_DATA_KNOWN_HASH;

    static {
        WELL_KNOWN_HASH = new MockHash(HashAlgorithm.SHA_384,
                Base64.getDecoder().decode("pKA/NF3xZhm+DOBne5MhXxq41eSYHyom/bAPvyCrrDNT8vt5eODhhtWG7LpQlHEE"));

        ALTERNATE_WELL_KNOWN_HASH = new MockHash(HashAlgorithm.SHA_384,
                Base64.getDecoder().decode("RXzuRQUHOT5zssgipY+PLujP4FrmQJQzVAvni+s52GcwtzkAnq+nRwwmW7noRqvx"));

        HASH_OF_WELL_KNOWN_HASHES = new MockHash(HashAlgorithm.SHA_384,
                Base64.getDecoder().decode("jJ2gb5dQn1Bxdz0fxLowPxakxynJFajOjm7PBbkIVuznXA/9Cfa4QlFAagSyvDTm"));

        LARGE_FILE_KNOWN_HASH = new MockHash(HashAlgorithm.SHA_384,
                Base64.getDecoder().decode("kL8LqTeUbOrlI2HXQu7ek+7nbMUCFW1z4byKrbfdgnQ3uAQ095PL5TmuEzDTD7Es"));

        IN_MEMORY_DATA = Base64.getDecoder()
                .decode("3K0By4fDo8jHaEoYKK7vtyb5KE1t1uYKG5p+r5ZNcnvNYCYZSTgAB6PpvHmsSGTwWov+42iTjzg9Eu4DBHtAdw==");

        IN_MEMORY_DATA_KNOWN_HASH = new MockHash(HashAlgorithm.SHA_384,
                Base64.getDecoder().decode("AhmB45prgDLfSo23+TqTa3U231O85iO424sEe+lgxVhPbyviG23klX+VRcNOAOMj"));
    }

    @BeforeAll
    public static void startup() {

    }

    @AfterAll
    public static void shutdown() {

    }

    @BeforeEach
    public void beforeTest() {
        WELL_KNOWN_HASH.setOverrideObjectId(null);
        WELL_KNOWN_HASH.setOverrideAlgorithm(null);
        WELL_KNOWN_HASH.setOverrideVersion(null);

        ALTERNATE_WELL_KNOWN_HASH.setOverrideObjectId(null);
        ALTERNATE_WELL_KNOWN_HASH.setOverrideAlgorithm(null);
        ALTERNATE_WELL_KNOWN_HASH.setOverrideVersion(null);

        HASH_OF_WELL_KNOWN_HASHES.setOverrideObjectId(null);
        HASH_OF_WELL_KNOWN_HASHES.setOverrideAlgorithm(null);
        HASH_OF_WELL_KNOWN_HASHES.setOverrideVersion(null);
    }

    @Test
    @Order(100)
    @DisplayName("Hash :: SHA_384 -> Hash of Hashes")
    public void testCryptoSha384HashOfHashes() throws NoSuchAlgorithmException {
        final Cryptography provider = Cryptography.getDefaultInstance();

        final Hash defaultHashOfHashes = provider
                .digestSync(WELL_KNOWN_HASH, ALTERNATE_WELL_KNOWN_HASH);

        final Hash explicitHashOfHashes = provider
                .digestSync(HashAlgorithm.SHA_384, WELL_KNOWN_HASH, ALTERNATE_WELL_KNOWN_HASH);

        assertEquals(HASH_OF_WELL_KNOWN_HASHES, defaultHashOfHashes);
        assertArrayEquals(HASH_OF_WELL_KNOWN_HASHES.getValue(), defaultHashOfHashes.getValue());

        assertEquals(HASH_OF_WELL_KNOWN_HASHES, explicitHashOfHashes);
        assertArrayEquals(HASH_OF_WELL_KNOWN_HASHES.getValue(), explicitHashOfHashes.getValue());


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
            final Hash explicitFileHash = provider.digestSync(HashAlgorithm.SHA_384, stream);

            assertNotNull(explicitFileHash);
            assertEquals(LARGE_FILE_KNOWN_HASH, explicitFileHash);
            assertArrayEquals(LARGE_FILE_KNOWN_HASH.getValue(), explicitFileHash.getValue());
        }

        assertEquals(1, DefaultCryptographyImpl.getHashAlgorithmCache().get().size());

    }

    @Test
    @Order(102)
    @DisplayName("Hash :: SHA_384 -> In Memory Data")
    public void testCryptoSha384InMemoryData() throws NoSuchAlgorithmException {
        final Cryptography provider = Cryptography.getDefaultInstance();

        final Hash defaultMemoryDataHash = provider.digestSync(IN_MEMORY_DATA);

        final Hash explicitMemoryDataHash = provider
                .digestSync(HashAlgorithm.SHA_384, IN_MEMORY_DATA);


        assertEquals(IN_MEMORY_DATA_KNOWN_HASH, defaultMemoryDataHash);
        assertArrayEquals(IN_MEMORY_DATA_KNOWN_HASH.getValue(), defaultMemoryDataHash.getValue());

        assertEquals(IN_MEMORY_DATA_KNOWN_HASH, explicitMemoryDataHash);
        assertArrayEquals(IN_MEMORY_DATA_KNOWN_HASH.getValue(), explicitMemoryDataHash.getValue());

        assertEquals(1, DefaultCryptographyImpl.getHashAlgorithmCache().get().size());

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
                .digestSync(HashAlgorithm.SHA_384, buffer);

        assertEquals(IN_MEMORY_DATA_KNOWN_HASH, defaultBufferHash);
        assertArrayEquals(IN_MEMORY_DATA_KNOWN_HASH.getValue(), defaultBufferHash.getValue());

        assertEquals(IN_MEMORY_DATA_KNOWN_HASH, explicitBufferHash);
        assertArrayEquals(IN_MEMORY_DATA_KNOWN_HASH.getValue(), explicitBufferHash.getValue());

        assertEquals(1, DefaultCryptographyImpl.getHashAlgorithmCache().get().size());

    }
}