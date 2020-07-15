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

package com.servercurio.fabric.security.impl;

import com.servercurio.fabric.io.ThrowingInputStream;
import com.servercurio.fabric.security.Cryptography;
import com.servercurio.fabric.security.CryptographyException;
import com.servercurio.fabric.security.Hash;
import com.servercurio.fabric.security.HashAlgorithm;
import com.servercurio.fabric.security.ImmutableHash;
import com.servercurio.fabric.security.MockHash;
import com.servercurio.fabric.security.spi.DigestProvider;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static com.servercurio.fabric.lang.ComparableConstants.EQUAL;
import static com.servercurio.fabric.lang.ComparableConstants.GREATER_THAN;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Cryptography: Hashing")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class CryptographyHashTests {

    private static final MockHash WELL_KNOWN_HASH;
    private static final MockHash ALTERNATE_WELL_KNOWN_HASH;
    private static final MockHash HASH_OF_WELL_KNOWN_HASHES;
    private static final MockHash HASH_OF_NULL_LEFT_HASHES;
    private static final MockHash HASH_OF_NULL_RIGHT_HASHES;

    private static final String LARGE_FILE_NAME =
            "8b3b606bb5cc9e6e4a05ee6091bb0fbb55d419d414189346e200b7cd240db4a58143bf32fcdea79bf8d71f04aae7adcb.bin";
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
                                                      .decode("91ToGuzfdK+VDc/57EZUmvBbDaTkOoFcTaR+nXKhsebBYyYzOfW2GQCMHnGVVrik"));

        HASH_OF_NULL_RIGHT_HASHES = new MockHash(HashAlgorithm.SHA_384,
                                                 Base64.getDecoder()
                                                       .decode("1F4jTbdJHows8y3NTinV6PLiwNe9fKCKfOKSZ+eL8vBxErjzdAv5g3JHgAzRZFMc"));

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
    @Order(25)
    @DisplayName("Hash :: HashAlgorithm -> Basic Enum")
    public void testCryptoHashAlgorithmBasicEnum() {
        final BouncyCastleProvider bcProv = new BouncyCastleProvider();
        assertEquals(384, HashAlgorithm.SHA_384.bits());
        assertEquals(48, HashAlgorithm.SHA_384.bytes());
        assertEquals(HashAlgorithm.SHA_384, HashAlgorithm.valueOf("SHA_384"));
        assertEquals(HashAlgorithm.SHA_384, HashAlgorithm.valueOf(HashAlgorithm.SHA_384.id()));
        assertEquals("SHA-384", HashAlgorithm.SHA_384.algorithmName());

        assertNull(HashAlgorithm.valueOf(-1));

        assertThrows(CryptographyException.class, HashAlgorithm.NONE::instance);
        assertThrows(CryptographyException.class, () -> HashAlgorithm.NONE.instance(bcProv));
        assertThrows(CryptographyException.class, () -> HashAlgorithm.SHA_384.instance("INVALID"));
    }

    @Test
    @Order(176)
    @DisplayName("Hash :: SHA_384 -> Async Byte Buffer")
    public void testCryptoSha384AsyncByteBuffer() throws ExecutionException, InterruptedException {
        final DigestProvider provider = Cryptography.newDefaultInstance().digest();

        final ByteBuffer defaultBuffer = ByteBuffer.allocateDirect(IN_MEMORY_DATA.length);
        defaultBuffer.put(IN_MEMORY_DATA).rewind();

        final ByteBuffer explicitBuffer = ByteBuffer.allocateDirect(IN_MEMORY_DATA.length);
        explicitBuffer.put(IN_MEMORY_DATA).rewind();

        final Future<Hash> defaultBufferHash = provider
                .digestAsync(defaultBuffer);

        final Future<Hash> explicitBufferHash = provider
                .digestAsync(HashAlgorithm.SHA_384, explicitBuffer);

        assertEquals(IN_MEMORY_DATA_KNOWN_HASH, defaultBufferHash.get());
        assertArrayEquals(IN_MEMORY_DATA_KNOWN_HASH.getValue(), defaultBufferHash.get().getValue());

        assertEquals(IN_MEMORY_DATA_KNOWN_HASH, explicitBufferHash.get());
        assertArrayEquals(IN_MEMORY_DATA_KNOWN_HASH.getValue(), explicitBufferHash.get().getValue());
    }

    @Test
    @Order(101)
    @DisplayName("Hash :: SHA_384 -> Async Hash of Hashes")
    public void testCryptoSha384AsyncHashOfHashes() throws Exception {
        try (final Cryptography crypto = Cryptography.newDefaultInstance()) {
            final DigestProvider provider = crypto.digest();

            final Future<Hash> defaultHashOfHashes = provider
                    .digestAsync(WELL_KNOWN_HASH, ALTERNATE_WELL_KNOWN_HASH);

            final Future<Hash> explicitHashOfHashes = provider
                    .digestAsync(HashAlgorithm.SHA_384, WELL_KNOWN_HASH, ALTERNATE_WELL_KNOWN_HASH);

            final Future<Hash> nullLeftHashOfHashes = provider.digestAsync((Hash) null, ALTERNATE_WELL_KNOWN_HASH);

            final Future<Hash> nullRightHashOfHashes = provider.digestAsync(WELL_KNOWN_HASH, null);

            assertEquals(HASH_OF_WELL_KNOWN_HASHES, defaultHashOfHashes.get());
            assertArrayEquals(HASH_OF_WELL_KNOWN_HASHES.getValue(), defaultHashOfHashes.get().getValue());

            assertEquals(HASH_OF_WELL_KNOWN_HASHES, explicitHashOfHashes.get());
            assertArrayEquals(HASH_OF_WELL_KNOWN_HASHES.getValue(), explicitHashOfHashes.get().getValue());

            assertEquals(HASH_OF_NULL_LEFT_HASHES, nullLeftHashOfHashes.get());
            assertEquals(HASH_OF_NULL_RIGHT_HASHES, nullRightHashOfHashes.get());
        }
    }

    @Test
    @Order(151)
    @DisplayName("Hash :: SHA_384 -> Async In Memory Data")
    public void testCryptoSha384AsyncInMemoryData() throws ExecutionException, InterruptedException {
        final DigestProvider provider = Cryptography.newDefaultInstance().digest();

        final Future<Hash> defaultMemoryDataHash = provider.digestAsync(IN_MEMORY_DATA);

        final Future<Hash> explicitMemoryDataHash = provider
                .digestAsync(HashAlgorithm.SHA_384, IN_MEMORY_DATA);


        assertEquals(IN_MEMORY_DATA_KNOWN_HASH, defaultMemoryDataHash.get());
        assertArrayEquals(IN_MEMORY_DATA_KNOWN_HASH.getValue(), defaultMemoryDataHash.get().getValue());

        assertEquals(IN_MEMORY_DATA_KNOWN_HASH, explicitMemoryDataHash.get());
        assertArrayEquals(IN_MEMORY_DATA_KNOWN_HASH.getValue(), explicitMemoryDataHash.get().getValue());
    }

    @Test
    @Order(126)
    @DisplayName("Hash :: SHA_384 -> Async Large File")
    public void testCryptoSha384AsyncLargeFile() throws IOException, ExecutionException, InterruptedException {
        final DigestProvider provider = Cryptography.newDefaultInstance().digest();
        final ClassLoader classLoader = getClass().getClassLoader();

        try (final InputStream stream = classLoader.getResourceAsStream(LARGE_FILE_NAME)) {
            final Future<Hash> defaultFileHash = provider.digestAsync(stream);

            assertNotNull(defaultFileHash);
            assertEquals(LARGE_FILE_KNOWN_HASH, defaultFileHash.get());
            assertArrayEquals(LARGE_FILE_KNOWN_HASH.getValue(), defaultFileHash.get().getValue());
        }

        try (final InputStream stream = classLoader.getResourceAsStream(LARGE_FILE_NAME)) {
            final Future<Hash> explicitFileHash = provider.digestAsync(HashAlgorithm.SHA_384, stream);

            assertNotNull(explicitFileHash);
            assertEquals(LARGE_FILE_KNOWN_HASH, explicitFileHash.get());
            assertArrayEquals(LARGE_FILE_KNOWN_HASH.getValue(), explicitFileHash.get().getValue());
        }


        try (
                final InputStream stream = classLoader.getResourceAsStream(LARGE_FILE_NAME);
                final ThrowingInputStream throwingStream = new ThrowingInputStream(stream)
        ) {
            assertThrows(ExecutionException.class, () -> {
                provider.digestAsync(HashAlgorithm.SHA_384, throwingStream).get();
            });
        }
    }

    @Test
    @Order(50)
    @DisplayName("Hash :: SHA_384 -> Basic Hash")
    public void testCryptoSha384BasicHash() throws Exception {
        try (final Cryptography provider = Cryptography.newDefaultInstance()) {

            final byte[] invalidLengthHash = new byte[HashAlgorithm.SHA_384.bytes() - 5];
            final byte[] validHashBytes = WELL_KNOWN_HASH.getValue();

            // Constructor Exceptions
            assertThrows(IllegalArgumentException.class, () -> new Hash(null, validHashBytes));
            assertThrows(IllegalArgumentException.class, () -> new Hash(HashAlgorithm.SHA_384, null));
            assertThrows(IllegalArgumentException.class, () -> new Hash(HashAlgorithm.SHA_384, invalidLengthHash));
            assertThrows(IllegalArgumentException.class, () -> new Hash(null));

            // Constructor Copies
            final Hash emptyCopy = new Hash(Hash.EMPTY);
            final Hash emptyRef = Hash.EMPTY;
            final Hash validCopy = new Hash(WELL_KNOWN_HASH);
            final Hash immutableCopy = new ImmutableHash(validCopy);
            final Hash immutable = new ImmutableHash(validCopy.getAlgorithm(), validCopy.getValue());

            // isEmpty Validations
            assertTrue(emptyCopy.isEmpty());
            assertFalse(validCopy.isEmpty());

            // CompareTo Validation
            assertEquals(Hash.EMPTY, emptyRef);
            assertNotEquals(null, Hash.EMPTY);

            assertEquals(EQUAL, Hash.EMPTY.compareTo(emptyCopy));
            assertEquals(EQUAL, Hash.EMPTY.compareTo(Hash.EMPTY));
            assertEquals(GREATER_THAN, Hash.EMPTY.compareTo(null));

            // toPrefix Validations
            assertEquals("a4a03f34", WELL_KNOWN_HASH.toPrefix());
            assertEquals("a4a03f345df1", WELL_KNOWN_HASH.toPrefix(6));
            assertThrows(IndexOutOfBoundsException.class, Hash.EMPTY::toPrefix);

            // toString/hashCode/equals Validations (using empty & actual hash values)
            assertNotNull(Hash.EMPTY.toString());
            assertNotEquals(0, validCopy.hashCode());

            assertEquals(Hash.EMPTY, emptyCopy);
            assertEquals(WELL_KNOWN_HASH, validCopy);

            // Assert immutable hash equals
            assertTrue(immutable.equals(validCopy));
            assertTrue(immutableCopy.equals(validCopy));
            assertFalse(validCopy.equals(immutableCopy));

            // setAlgorithm Validations
            assertThrows(IllegalArgumentException.class, () -> emptyCopy.setAlgorithm(null));
            assertThrows(UnsupportedOperationException.class, () -> immutableCopy.setAlgorithm(HashAlgorithm.SHA_384));

            emptyCopy.setAlgorithm(HashAlgorithm.SHA_384);
            assertEquals(HashAlgorithm.SHA_384.bytes(), emptyCopy.getValue().length);

            // setValue Validations
            assertThrows(IllegalArgumentException.class, () -> validCopy.setValue(null));
            assertThrows(IllegalArgumentException.class, () -> validCopy.setValue(invalidLengthHash));
            assertThrows(UnsupportedOperationException.class, () -> immutableCopy.setValue(null));

            validCopy.setValue(new byte[HashAlgorithm.SHA_384.bytes()]);
            assertTrue(validCopy.isEmpty());

            // immutable getValue Validations
            assertNotSame(validCopy.getValue(), immutableCopy.getValue());
            assertNotSame(validCopy.getValue(), immutable.getValue());
        }
    }

    @Test
    @Order(175)
    @DisplayName("Hash :: SHA_384 -> Sync Byte Buffer")
    public void testCryptoSha384SyncByteBuffer() {
        final DigestProvider provider = Cryptography.newDefaultInstance().digest();

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
    }

    @Test
    @Order(100)
    @DisplayName("Hash :: SHA_384 -> Sync Hash of Hashes")
    public void testCryptoSha384SyncHashOfHashes() throws Exception {
        try (final Cryptography crypto = Cryptography.newDefaultInstance()) {
            final DigestProvider provider = crypto.digest();

            final Hash defaultHashOfHashes = provider
                    .digestSync(WELL_KNOWN_HASH, ALTERNATE_WELL_KNOWN_HASH);

            final Hash explicitHashOfHashes = provider
                    .digestSync(HashAlgorithm.SHA_384, WELL_KNOWN_HASH, ALTERNATE_WELL_KNOWN_HASH);

            final Hash nullLeftHashOfHashes = provider.digestSync((Hash) null, ALTERNATE_WELL_KNOWN_HASH);

            final Hash nullRightHashOfHashes = provider.digestSync(WELL_KNOWN_HASH, null);

            assertEquals(HASH_OF_WELL_KNOWN_HASHES, defaultHashOfHashes);
            assertArrayEquals(HASH_OF_WELL_KNOWN_HASHES.getValue(), defaultHashOfHashes.getValue());

            assertEquals(HASH_OF_WELL_KNOWN_HASHES, explicitHashOfHashes);
            assertArrayEquals(HASH_OF_WELL_KNOWN_HASHES.getValue(), explicitHashOfHashes.getValue());

            assertEquals(HASH_OF_NULL_LEFT_HASHES, nullLeftHashOfHashes);
            assertEquals(HASH_OF_NULL_RIGHT_HASHES, nullRightHashOfHashes);

        }
    }

    @Test
    @Order(150)
    @DisplayName("Hash :: SHA_384 -> Sync In Memory Data")
    public void testCryptoSha384SyncInMemoryData() {
        final DigestProvider provider = Cryptography.newDefaultInstance().digest();

        final Hash defaultMemoryDataHash = provider.digestSync(IN_MEMORY_DATA);

        final Hash explicitMemoryDataHash = provider
                .digestSync(HashAlgorithm.SHA_384, IN_MEMORY_DATA);


        assertEquals(IN_MEMORY_DATA_KNOWN_HASH, defaultMemoryDataHash);
        assertArrayEquals(IN_MEMORY_DATA_KNOWN_HASH.getValue(), defaultMemoryDataHash.getValue());

        assertEquals(IN_MEMORY_DATA_KNOWN_HASH, explicitMemoryDataHash);
        assertArrayEquals(IN_MEMORY_DATA_KNOWN_HASH.getValue(), explicitMemoryDataHash.getValue());
    }

    @Test
    @Order(125)
    @DisplayName("Hash :: SHA_384 -> Sync Large File")
    public void testCryptoSha384SyncLargeFile() throws IOException {
        final DigestProvider provider = Cryptography.newDefaultInstance().digest();
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


        try (
                final InputStream stream = classLoader.getResourceAsStream(LARGE_FILE_NAME);
                final ThrowingInputStream throwingStream = new ThrowingInputStream(stream)
        ) {
            assertThrows(CryptographyException.class, () -> {
                provider.digestSync(HashAlgorithm.SHA_384, throwingStream);
            });
        }
    }
}
