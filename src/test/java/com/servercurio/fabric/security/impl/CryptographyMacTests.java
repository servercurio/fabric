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
import com.servercurio.fabric.security.MacAlgorithm;
import com.servercurio.fabric.security.MockHash;
import com.servercurio.fabric.security.spi.DigestProvider;
import com.servercurio.fabric.security.spi.MacProvider;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
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
import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Cryptography: Message Authentication")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class CryptographyMacTests {

    private static final MockHash WELL_KNOWN_HASH;
    private static final MockHash ALTERNATE_WELL_KNOWN_HASH;
    private static final MockHash HASH_OF_WELL_KNOWN_HASHES;
    private static final MockHash HASH_OF_NULL_LEFT_HASHES;
    private static final MockHash HASH_OF_NULL_RIGHT_HASHES;

    private static final byte[] SECRET_KEY_BYTES =
            Base64.getDecoder().decode("GkAMxoa7oOR9qtHhNhs4DvaO1NAsD4U0sBDekIC/3ahXdiBcRCjJSTIUCJ8Xzw75");

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
                      .decode("xlV3JkUBerW3mZvckd2AoJ2EWIeL2vVBGEzdSKStp75gh0ftKZQ82ouOFEyDj8fT"));

        HASH_OF_NULL_LEFT_HASHES = new MockHash(HashAlgorithm.SHA_384,
                Base64.getDecoder()
                      .decode("1ASZCIrQFrH0QmwzJoyHg1KVjf4nI50nBDItuDSAEOONYVD9nhsWBOoGCTyRkIgT"));

        HASH_OF_NULL_RIGHT_HASHES = new MockHash(HashAlgorithm.SHA_384,
                Base64.getDecoder()
                      .decode("VmmAygzY5XUjBztz8UdBBjGkhvqjuRNdBF2BOkBBMhFfQjMD6qi2FbDUmeRqihli"));

        LARGE_FILE_KNOWN_HASH = new MockHash(HashAlgorithm.SHA_384,
                Base64.getDecoder()
                      .decode("tkSKrfVOE5Ini+fs+ixo+Pwly9SslX192dOEq7Rs7qzlH7aNPyp42DuzziFTJJQy"));

        IN_MEMORY_DATA = Base64.getDecoder()
                               .decode("3K0By4fDo8jHaEoYKK7vtyb5KE1t1uYKG5p+r5ZNcnvNYCYZSTgAB6PpvHmsSGTwWov+42iTjzg9Eu4DBHtAdw==");

        IN_MEMORY_DATA_KNOWN_HASH = new MockHash(HashAlgorithm.SHA_384,
                Base64.getDecoder()
                      .decode("/PmW1EA3rAxDhSoZnvBAVvDa7HTCQrbselERSNGu7IcwJEzCvJYwkIjAf1N8ZiSK"));
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
    @Order(176)
    @DisplayName("MAC :: HmacSHA384 -> Async Byte Buffer")
    public void testCryptoHmacSha384AsyncByteBuffer() throws Exception {
        try (final Cryptography crypto = Cryptography.newDefaultInstance()) {
            final MacProvider provider = crypto.mac();

            final SecretKey secretKey = new SecretKeySpec(SECRET_KEY_BYTES, MacAlgorithm.HMAC_SHA_384.algorithmName());

            final ByteBuffer defaultBuffer = ByteBuffer.allocateDirect(IN_MEMORY_DATA.length);
            defaultBuffer.put(IN_MEMORY_DATA).rewind();

            final ByteBuffer explicitBuffer = ByteBuffer.allocateDirect(IN_MEMORY_DATA.length);
            explicitBuffer.put(IN_MEMORY_DATA).rewind();

            final Future<Hash> defaultBufferHash = provider
                    .authenticateAsync(secretKey, defaultBuffer);

            final Future<Hash> explicitBufferHash = provider
                    .authenticateAsync(MacAlgorithm.HMAC_SHA_384, secretKey, explicitBuffer);

            assertEquals(IN_MEMORY_DATA_KNOWN_HASH, defaultBufferHash.get());
            assertArrayEquals(IN_MEMORY_DATA_KNOWN_HASH.getValue(), defaultBufferHash.get().getValue());

            assertEquals(IN_MEMORY_DATA_KNOWN_HASH, explicitBufferHash.get());
            assertArrayEquals(IN_MEMORY_DATA_KNOWN_HASH.getValue(), explicitBufferHash.get().getValue());
        }
    }

    @Test
    @Order(101)
    @DisplayName("MAC :: HmacSHA384 -> Async Hash of Hashes")
    public void testCryptoHmacSha384AsyncHashOfHashes() throws Exception {
        try (final Cryptography crypto = Cryptography.newDefaultInstance()) {
            final MacProvider provider = crypto.mac();

            final SecretKey secretKey = new SecretKeySpec(SECRET_KEY_BYTES, MacAlgorithm.HMAC_SHA_384.algorithmName());

            final Future<Hash> defaultHashOfHashes = provider
                    .authenticateAsync(secretKey, WELL_KNOWN_HASH, ALTERNATE_WELL_KNOWN_HASH);

            final Future<Hash> explicitHashOfHashes = provider
                    .authenticateAsync(MacAlgorithm.HMAC_SHA_384, secretKey, WELL_KNOWN_HASH,
                            ALTERNATE_WELL_KNOWN_HASH);

            final Future<Hash> nullLeftHashOfHashes =
                    provider.authenticateAsync(secretKey, (Hash) null, ALTERNATE_WELL_KNOWN_HASH);

            final Future<Hash> nullRightHashOfHashes =
                    provider.authenticateAsync(secretKey, WELL_KNOWN_HASH, (Hash) null);

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
    @DisplayName("MAC :: HmacSHA384 -> Async In Memory Data")
    public void testCryptoHmacSha384AsyncInMemoryData() throws Exception {
        try (final Cryptography crypto = Cryptography.newDefaultInstance()) {
            final MacProvider provider = crypto.mac();

            final SecretKey secretKey = new SecretKeySpec(SECRET_KEY_BYTES, MacAlgorithm.HMAC_SHA_384.algorithmName());

            final Future<Hash> defaultMemoryDataHash = provider.authenticateAsync(secretKey, IN_MEMORY_DATA);

            final Future<Hash> explicitMemoryDataHash = provider
                    .authenticateAsync(MacAlgorithm.HMAC_SHA_384, secretKey, IN_MEMORY_DATA);


            assertEquals(IN_MEMORY_DATA_KNOWN_HASH, defaultMemoryDataHash.get());
            assertArrayEquals(IN_MEMORY_DATA_KNOWN_HASH.getValue(), defaultMemoryDataHash.get().getValue());

            assertEquals(IN_MEMORY_DATA_KNOWN_HASH, explicitMemoryDataHash.get());
            assertArrayEquals(IN_MEMORY_DATA_KNOWN_HASH.getValue(), explicitMemoryDataHash.get().getValue());
        }
    }

    @Test
    @Order(25)
    @DisplayName("MAC :: MacAlgorithm -> Basic Enum")
    public void testCryptoMacAlgorithmBasicEnum() {
        final BouncyCastleProvider bcProv = new BouncyCastleProvider();
        assertEquals(384, MacAlgorithm.HMAC_SHA_384.bits());
        assertEquals(48, MacAlgorithm.HMAC_SHA_384.bytes());
        assertEquals(MacAlgorithm.HMAC_SHA_384, MacAlgorithm.valueOf("HMAC_SHA_384"));
        assertEquals(MacAlgorithm.HMAC_SHA_384, MacAlgorithm.valueOf(MacAlgorithm.HMAC_SHA_384.id()));
        assertEquals("HmacSHA384", MacAlgorithm.HMAC_SHA_384.algorithmName());

        assertNull(MacAlgorithm.valueOf(-1));

        assertThrows(CryptographyException.class, MacAlgorithm.NONE::instance);
        assertThrows(CryptographyException.class, () -> MacAlgorithm.NONE.instance(bcProv));
        assertThrows(CryptographyException.class, () -> MacAlgorithm.HMAC_SHA_384.instance("INVALID"));

        assertDoesNotThrow(() -> MacAlgorithm.HMAC_SHA_384.instance(bcProv));
        assertDoesNotThrow(() -> MacAlgorithm.HMAC_SHA_384.instance("SunJCE"));
    }

    @Test
    @Order(126)
    @DisplayName("MAC :: HmacSHA384 -> Async Large File")
    public void testCryptoHmacSha384AsyncLargeFile() throws Exception {
        try (final Cryptography crypto = Cryptography.newDefaultInstance()) {
            final MacProvider provider = crypto.mac();
            final ClassLoader classLoader = getClass().getClassLoader();

            final SecretKey secretKey = new SecretKeySpec(SECRET_KEY_BYTES, MacAlgorithm.HMAC_SHA_384.algorithmName());

            try (final InputStream stream = classLoader.getResourceAsStream(LARGE_FILE_NAME)) {
                final Future<Hash> defaultFileHash = provider.authenticateAsync(secretKey, stream);

                assertNotNull(defaultFileHash);
                assertEquals(LARGE_FILE_KNOWN_HASH, defaultFileHash.get());
                assertArrayEquals(LARGE_FILE_KNOWN_HASH.getValue(), defaultFileHash.get().getValue());
            }

            try (final InputStream stream = classLoader.getResourceAsStream(LARGE_FILE_NAME)) {
                final Future<Hash> explicitFileHash =
                        provider.authenticateAsync(MacAlgorithm.HMAC_SHA_384, secretKey, stream);

                assertNotNull(explicitFileHash);
                assertEquals(LARGE_FILE_KNOWN_HASH, explicitFileHash.get());
                assertArrayEquals(LARGE_FILE_KNOWN_HASH.getValue(), explicitFileHash.get().getValue());
            }


            try (
                    final InputStream stream = classLoader.getResourceAsStream(LARGE_FILE_NAME);
                    final ThrowingInputStream throwingStream = new ThrowingInputStream(stream)
            ) {
                assertThrows(ExecutionException.class, () -> {
                    provider.authenticateAsync(MacAlgorithm.HMAC_SHA_384, secretKey, throwingStream).get();
                });
            }
        }
    }


    @Test
    @Order(175)
    @DisplayName("MAC :: HmacSHA384 -> Sync Byte Buffer")
    public void testCryptoHmacSha384SyncByteBuffer() throws Exception {
        try (final Cryptography crypto = Cryptography.newDefaultInstance()) {
            final MacProvider provider = crypto.mac();

            final ByteBuffer buffer = ByteBuffer.allocateDirect(IN_MEMORY_DATA.length);
            buffer.put(IN_MEMORY_DATA).rewind();

            final SecretKey secretKey = new SecretKeySpec(SECRET_KEY_BYTES, MacAlgorithm.HMAC_SHA_384.algorithmName());

            final Hash defaultBufferHash = provider
                    .authenticateSync(secretKey, buffer);

            buffer.rewind();

            final Hash explicitBufferHash = provider
                    .authenticateSync(MacAlgorithm.HMAC_SHA_384, secretKey, buffer);

            assertEquals(IN_MEMORY_DATA_KNOWN_HASH, defaultBufferHash);
            assertArrayEquals(IN_MEMORY_DATA_KNOWN_HASH.getValue(), defaultBufferHash.getValue());

            assertEquals(IN_MEMORY_DATA_KNOWN_HASH, explicitBufferHash);
            assertArrayEquals(IN_MEMORY_DATA_KNOWN_HASH.getValue(), explicitBufferHash.getValue());
        }
    }

    @Test
    @Order(100)
    @DisplayName("MAC :: HmacSHA384 -> Sync Hash of Hashes")
    public void testCryptoHmacSha384SyncHashOfHashes() throws Exception {
        try (final Cryptography crypto = Cryptography.newDefaultInstance()) {
            final MacProvider provider = crypto.mac();

            final SecretKey secretKey = new SecretKeySpec(SECRET_KEY_BYTES, MacAlgorithm.HMAC_SHA_384.algorithmName());

            final Hash defaultHashOfHashes = provider
                    .authenticateSync(secretKey, WELL_KNOWN_HASH, ALTERNATE_WELL_KNOWN_HASH);

            final Hash explicitHashOfHashes = provider
                    .authenticateSync(MacAlgorithm.HMAC_SHA_384, secretKey, WELL_KNOWN_HASH, ALTERNATE_WELL_KNOWN_HASH);

            final Hash nullLeftHashOfHashes = provider.authenticateSync(secretKey, (Hash) null, ALTERNATE_WELL_KNOWN_HASH);

            final Hash nullRightHashOfHashes = provider.authenticateSync(secretKey, WELL_KNOWN_HASH, (Hash)null);

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
    @DisplayName("MAC :: HmacSHA384 -> Sync In Memory Data")
    public void testCryptoHmacSha384SyncInMemoryData() throws Exception {
        try (final Cryptography crypto = Cryptography.newDefaultInstance()) {
            final MacProvider provider = crypto.mac();

            final SecretKey secretKey = new SecretKeySpec(SECRET_KEY_BYTES, MacAlgorithm.HMAC_SHA_384.algorithmName());

            final Hash defaultMemoryDataHash = provider.authenticateSync(secretKey, IN_MEMORY_DATA);

            final Hash explicitMemoryDataHash = provider
                    .authenticateSync(MacAlgorithm.HMAC_SHA_384, secretKey, IN_MEMORY_DATA);


            assertEquals(IN_MEMORY_DATA_KNOWN_HASH, defaultMemoryDataHash);
            assertArrayEquals(IN_MEMORY_DATA_KNOWN_HASH.getValue(), defaultMemoryDataHash.getValue());

            assertEquals(IN_MEMORY_DATA_KNOWN_HASH, explicitMemoryDataHash);
            assertArrayEquals(IN_MEMORY_DATA_KNOWN_HASH.getValue(), explicitMemoryDataHash.getValue());
        }
    }

    @Test
    @Order(125)
    @DisplayName("MAC :: HmacSHA384 -> Sync Large File")
    public void testCryptoHmacSha384SyncLargeFile() throws Exception {
        try (final Cryptography crypto = Cryptography.newDefaultInstance()) {
            final MacProvider provider = crypto.mac();
            final ClassLoader classLoader = getClass().getClassLoader();

            final SecretKey secretKey = new SecretKeySpec(SECRET_KEY_BYTES, MacAlgorithm.HMAC_SHA_384.algorithmName());

            try (final InputStream stream = classLoader.getResourceAsStream(LARGE_FILE_NAME)) {
                final Hash defaultFileHash = provider.authenticateSync(secretKey, stream);

                assertNotNull(defaultFileHash);
                assertEquals(LARGE_FILE_KNOWN_HASH, defaultFileHash);
                assertArrayEquals(LARGE_FILE_KNOWN_HASH.getValue(), defaultFileHash.getValue());
            }

            try (final InputStream stream = classLoader.getResourceAsStream(LARGE_FILE_NAME)) {
                final Hash explicitFileHash = provider.authenticateSync(MacAlgorithm.HMAC_SHA_384, secretKey, stream);

                assertNotNull(explicitFileHash);
                assertEquals(LARGE_FILE_KNOWN_HASH, explicitFileHash);
                assertArrayEquals(LARGE_FILE_KNOWN_HASH.getValue(), explicitFileHash.getValue());
            }


            try (
                    final InputStream stream = classLoader.getResourceAsStream(LARGE_FILE_NAME);
                    final ThrowingInputStream throwingStream = new ThrowingInputStream(stream)
            ) {
                assertThrows(CryptographyException.class, () -> {
                    provider.authenticateSync(MacAlgorithm.HMAC_SHA_384, secretKey, throwingStream);
                });
            }
        }
    }
}
