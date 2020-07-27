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

import com.servercurio.fabric.security.CipherAlgorithm;
import com.servercurio.fabric.security.CipherMode;
import com.servercurio.fabric.security.CipherPadding;
import com.servercurio.fabric.security.CipherTransformation;
import com.servercurio.fabric.security.Cryptography;
import com.servercurio.fabric.security.CryptographyException;
import com.servercurio.fabric.security.Hash;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.stream.Stream;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.function.ThrowingSupplier;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import static com.servercurio.fabric.lang.ComparableConstants.EQUAL;
import static com.servercurio.fabric.lang.ComparableConstants.GREATER_THAN;
import static com.servercurio.fabric.lang.ComparableConstants.LESS_THAN;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Cryptography: Encryption")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class CryptographyEncryptionTests {

    private static final int AES_KEY_SIZE = 256;

    private static final String LARGE_FILE_NAME = "8b3b606bb5cc9e6e4a05ee6091bb0fbb55d419d414189346e200b7cd240db4a58143bf32fcdea79bf8d71f04aae7adcb.bin";
    private static final String ENCRYPTED_LARGE_FILE_NAME = "8b3b606bb5cc9e6e4a05ee6091bb0fbb55d419d414189346e200b7cd240db4a58143bf32fcdea79bf8d71f04aae7adcb.enc";
    private static final String DECRYPTED_LARGE_FILE_NAME = "8b3b606bb5cc9e6e4a05ee6091bb0fbb55d419d414189346e200b7cd240db4a58143bf32fcdea79bf8d71f04aae7adcb.dec";

    public static Stream<CipherTransformation> transformationSource() {
        return Stream.of(
                new CipherTransformation(),
                new CipherTransformation(CipherAlgorithm.AES, CipherMode.CBC, CipherPadding.PKCS5),
                new CipherTransformation(CipherAlgorithm.AES, CipherMode.CTR, CipherPadding.NONE));
    }

    @Test
    @Order(25)
    @DisplayName("Encryption :: CipherAlgorithm -> Basic Enum")
    public void testCryptoCipherAlgorithmBasicEnum() {
        assertEquals(1, CipherAlgorithm.AES.id());
        assertEquals("AES", CipherAlgorithm.AES.keyAlgorithmName());
        assertEquals(CipherAlgorithm.AES, CipherAlgorithm.valueOf("AES"));
        assertEquals(CipherAlgorithm.AES, CipherAlgorithm.valueOf(CipherAlgorithm.AES.id()));
        assertEquals("AES", CipherAlgorithm.AES.algorithmName());

        assertNull(CipherAlgorithm.valueOf(-1));

        assertEquals(1, CipherMode.CBC.id());
        assertEquals("CBC", CipherMode.CBC.modeName());
        assertEquals(CipherMode.OFB8, CipherMode.valueOf("OFB8"));
        assertEquals(CipherMode.GCM, CipherMode.valueOf(CipherMode.GCM.id()));
        assertNull(CipherMode.valueOf(-1));

        assertEquals(1, CipherPadding.OAEP.id());
        assertEquals("PKCS5Padding", CipherPadding.PKCS5.paddingName());
        assertEquals(CipherPadding.PKCS5, CipherPadding.valueOf("PKCS5"));
        assertEquals(CipherPadding.PKCS5, CipherPadding.valueOf(CipherPadding.PKCS5.id()));
        assertNull(CipherPadding.valueOf(-1));
    }

    @ParameterizedTest
    @Order(150)
    @DisplayName("Encryption :: Cipher -> Async Byte Array Encryption")
    @ValueSource(ints = {8, 10, 12, 16, 32, 48, 64, 100, 123})
    public void testCryptoCipherAsyncByteArrayEncryption(int bufferSize) throws Exception {

        try (final Cryptography provider = Cryptography.newDefaultInstance()) {
            final byte[] sourceData = new byte[bufferSize];

            // Acquire random and generate random source data
            final SecureRandom random = SecureRandom.getInstance("NativePRNGNonBlocking");
            random.nextBytes(sourceData);

            // Compute source hash
            final Hash sourceHash = provider.digest().digestSync(sourceData);

            // Setup OTP structures
            final Future<byte[]> nonceFuture = provider.encryption().nonceAsync();

            final KeyGenerator keyGenerator = KeyGenerator.getInstance(CipherAlgorithm.AES.keyAlgorithmName());
            keyGenerator.init(AES_KEY_SIZE, random);

            final SecretKey secretKey = keyGenerator.generateKey();
            assertNotNull(secretKey);

            // Get the nonce
            final byte[] iv = nonceFuture.get();

            // Encrypt
            final Future<byte[]> encryptFuture = provider.encryption().encryptAsync(secretKey, iv, sourceData);
            assertNotNull(encryptFuture);
            final byte[] cipherText = encryptFuture.get();

            // Decrypt
            final Future<byte[]> decryptFuture = provider.encryption().decryptAsync(secretKey, iv, cipherText);
            assertNotNull(decryptFuture);
            final byte[] clearText = decryptFuture.get();

            // Compute decrypted hash
            final Hash decryptedHash = provider.digest().digestSync(clearText);

            assertEquals(sourceHash, decryptedHash);
            assertArrayEquals(sourceData, clearText);
        }

    }

    @ParameterizedTest
    @Order(200)
    @DisplayName("Encryption :: Cipher -> Async Byte Buffer Encryption")
    @ValueSource(ints = {8, 10, 12, 16, 32, 48, 64, 100, 123})
    public void testCryptoCipherAsyncByteBufferEncryption(int bufferSize) throws Exception {

        try (final Cryptography provider = Cryptography.newDefaultInstance()) {
            final byte[] sourceData = new byte[bufferSize];

            // Acquire random and generate random source data
            final SecureRandom random = SecureRandom.getInstance("NativePRNGNonBlocking");
            random.nextBytes(sourceData);

            // Compute source hash
            final Hash sourceHash = provider.digest().digestSync(sourceData);

            // Setup OTP structures
            final Future<byte[]> nonceFuture = provider.encryption().nonceAsync();

            final KeyGenerator keyGenerator = KeyGenerator.getInstance(CipherAlgorithm.AES.keyAlgorithmName());
            keyGenerator.init(AES_KEY_SIZE, random);

            final SecretKey secretKey = keyGenerator.generateKey();
            assertNotNull(secretKey);

            // Get the nonce
            final byte[] iv = nonceFuture.get();

            // Encrypt
            final Future<ByteBuffer> encryptFuture =
                    provider.encryption().encryptAsync(secretKey, iv, ByteBuffer.wrap(sourceData));
            assertNotNull(encryptFuture);
            final ByteBuffer cipherText = encryptFuture.get();

            // Decrypt
            final Future<ByteBuffer> decryptFuture = provider.encryption().decryptAsync(secretKey, iv, cipherText);
            assertNotNull(decryptFuture);
            final ByteBuffer clearText = decryptFuture.get();

            // Compute decrypted hash
            final Hash decryptedHash = provider.digest().digestSync(clearText);

            assertEquals(sourceHash, decryptedHash);
            assertArrayEquals(sourceData, clearText.array());
        }

    }

    @Test
    @Order(250)
    @DisplayName("Encryption :: Cipher -> Async Exceptions")
    public void testCryptoCipherAsyncExceptions() throws Exception {

        try (final Cryptography provider = Cryptography.newDefaultInstance()) {
            final CipherTransformation noneTransformation =
                    new CipherTransformation(CipherAlgorithm.NONE, CipherMode.NONE, CipherPadding.NONE);

            final byte[] sourceData = new byte[100];
            final byte[] zeroLengthIv = new byte[0];

            final SecureRandom random = SecureRandom.getInstance("NativePRNGNonBlocking");
            random.nextBytes(sourceData);

            final KeyGenerator keyGenerator = KeyGenerator.getInstance(CipherAlgorithm.AES.keyAlgorithmName());
            keyGenerator.init(AES_KEY_SIZE, random);

            final SecretKey secretKey = keyGenerator.generateKey();


            assertThrows(ExecutionException.class, () -> provider.encryption().nonceAsync(noneTransformation).get());

            try (final ByteArrayInputStream iStream = new ByteArrayInputStream(sourceData);
                 final ByteArrayOutputStream oStream = new ByteArrayOutputStream()) {
                assertThrows(ExecutionException.class,
                        () -> provider.encryption().encryptAsync(secretKey, zeroLengthIv, iStream, oStream).get());

                assertThrows(ExecutionException.class,
                        () -> provider.encryption().decryptAsync(secretKey, zeroLengthIv, iStream, oStream).get());
            }

            assertThrows(ExecutionException.class,
                    () -> provider.encryption().encryptAsync(secretKey, zeroLengthIv, sourceData).get());

            assertThrows(ExecutionException.class,
                    () -> provider.encryption().decryptAsync(secretKey, zeroLengthIv, sourceData).get());

            assertThrows(ExecutionException.class,
                    () -> provider.encryption()
                                  .encryptAsync(secretKey, zeroLengthIv, ByteBuffer.wrap(sourceData))
                                  .get());

            assertThrows(ExecutionException.class,
                    () -> provider.encryption()
                                  .decryptAsync(secretKey, zeroLengthIv, ByteBuffer.wrap(sourceData))
                                  .get());
        }

    }

    @ParameterizedTest
    @Order(100)
    @DisplayName("Encryption :: Cipher -> Async Stream Encryption")
    @MethodSource("transformationSource")
    public void testCryptoCipherAsyncStreamEncryption(CipherTransformation transformation,
                                                      @TempDir File tempDir) throws Exception {

        final boolean usingDefaults = Objects.equals(new CipherTransformation(), transformation);

        assertNotNull(tempDir);
        assertTrue(tempDir::exists);
        assertTrue(tempDir::isDirectory);

        final File encryptedFile = new File(tempDir, ENCRYPTED_LARGE_FILE_NAME);
        final File decryptedFile = new File(tempDir, DECRYPTED_LARGE_FILE_NAME);

        final ClassLoader classLoader = getClass().getClassLoader();

        final Future<Hash> sourceHashFuture;
        final Hash sourceHash;
        try (final Cryptography provider = Cryptography.newDefaultInstance();
             final InputStream sourceStream = classLoader.getResourceAsStream(LARGE_FILE_NAME)) {

            assertNotNull(sourceStream);

            // Compute source hash
            sourceHashFuture = provider.digest().digestAsync(sourceStream);
            assertNotNull(sourceHashFuture);

            sourceHash = sourceHashFuture.get();
            assertNotNull(sourceHash);
        }

        try (final Cryptography provider = Cryptography.newDefaultInstance();
             final InputStream sourceStream = classLoader.getResourceAsStream(LARGE_FILE_NAME)) {

            assertNotNull(sourceStream);

            // Find a secure random source
            final SecureRandom random = SecureRandom.getInstance("NativePRNGNonBlocking");

            // Setup OTP structures
            final Future<byte[]> nonceFuture = provider.encryption().nonceAsync(transformation);

            final KeyGenerator keyGenerator = KeyGenerator.getInstance(CipherAlgorithm.AES.keyAlgorithmName());
            keyGenerator.init(AES_KEY_SIZE, random);

            final SecretKey secretKey = keyGenerator.generateKey();
            assertNotNull(secretKey);

            final byte[] iv = nonceFuture.get();

            // Encrypt
            final Future<?> encryptFuture;
            try (final FileOutputStream cipherStream = new FileOutputStream(encryptedFile)) {
                if (usingDefaults) {
                    encryptFuture =
                            provider.encryption().encryptAsync(secretKey, iv, sourceStream, cipherStream);
                } else {
                    encryptFuture =
                            provider.encryption()
                                    .encryptAsync(transformation, secretKey, iv, sourceStream, cipherStream);
                }

                assertNotNull(encryptFuture);
                encryptFuture.get();
            }


            // Decrypt
            final Future<?> decryptFuture;
            try (final FileInputStream cipherStream = new FileInputStream(encryptedFile);
                 final FileOutputStream clearStream = new FileOutputStream(decryptedFile)) {
                if (usingDefaults) {
                    decryptFuture =
                            provider.encryption().decryptAsync(secretKey, iv, cipherStream, clearStream);
                } else {
                    decryptFuture =
                            provider.encryption()
                                    .decryptAsync(transformation, secretKey, iv, cipherStream, clearStream);
                }

                assertNotNull(decryptFuture);
                decryptFuture.get();
            }


            // Hash Decrypted Stream
            final Future<Hash> decryptedHashFuture;
            final Hash decryptedHash;
            try (final FileInputStream clearStream = new FileInputStream(decryptedFile)) {
                decryptedHashFuture = provider.digest().digestAsync(clearStream);
                assertNotNull(decryptedHashFuture);

                decryptedHash = decryptedHashFuture.get();
                assertNotNull(decryptedHash);
            }

            assertEquals(sourceHash, decryptedHash);
        }
    }

    @ParameterizedTest
    @Order(125)
    @DisplayName("Encryption :: Cipher -> Sync Byte Array Encryption")
    @ValueSource(ints = {8, 10, 12, 16, 32, 48, 64, 100, 123})
    public void testCryptoCipherSyncByteArrayEncryption(int bufferSize) throws Exception {

        try (final Cryptography provider = Cryptography.newDefaultInstance()) {
            final byte[] sourceData = new byte[bufferSize];

            // Acquire random and generate random source data
            final SecureRandom random = SecureRandom.getInstance("NativePRNGNonBlocking");
            random.nextBytes(sourceData);

            // Compute source hash
            final Hash sourceHash = provider.digest().digestSync(sourceData);

            // Setup OTP structures
            final byte[] iv = provider.encryption().nonceSync();

            final KeyGenerator keyGenerator = KeyGenerator.getInstance(CipherAlgorithm.AES.keyAlgorithmName());
            keyGenerator.init(AES_KEY_SIZE, random);

            final SecretKey secretKey = keyGenerator.generateKey();
            assertNotNull(secretKey);


            // Encrypt
            final byte[] cipherText = provider.encryption().encryptSync(secretKey, iv, sourceData);
            assertNotNull(cipherText);

            // Decrypt
            final byte[] clearText = provider.encryption().decryptSync(secretKey, iv, cipherText);
            assertNotNull(clearText);

            // Compute decrypted hash
            final Hash decryptedHash = provider.digest().digestSync(clearText);

            assertEquals(sourceHash, decryptedHash);
            assertArrayEquals(sourceData, clearText);
        }

    }

    @ParameterizedTest
    @Order(175)
    @DisplayName("Encryption :: Cipher -> Sync Byte Buffer Encryption")
    @ValueSource(ints = {8, 10, 12, 16, 32, 48, 64, 100, 123})
    public void testCryptoCipherSyncByteBufferEncryption(int bufferSize) throws Exception {

        try (final Cryptography provider = Cryptography.newDefaultInstance()) {
            final byte[] sourceData = new byte[bufferSize];

            // Acquire random and generate random source data
            final SecureRandom random = SecureRandom.getInstance("NativePRNGNonBlocking");
            random.nextBytes(sourceData);

            // Compute source hash
            final Hash sourceHash = provider.digest().digestSync(sourceData);

            // Setup OTP structures
            final byte[] iv = provider.encryption().nonceSync();

            final KeyGenerator keyGenerator = KeyGenerator.getInstance(CipherAlgorithm.AES.keyAlgorithmName());
            keyGenerator.init(AES_KEY_SIZE, random);

            final SecretKey secretKey = keyGenerator.generateKey();
            assertNotNull(secretKey);


            // Encrypt
            final ByteBuffer cipherText = provider.encryption().encryptSync(secretKey, iv, ByteBuffer.wrap(sourceData));
            assertNotNull(cipherText);

            // Decrypt
            final ByteBuffer clearText = provider.encryption().decryptSync(secretKey, iv, cipherText);
            assertNotNull(clearText);

            // Compute decrypted hash
            final Hash decryptedHash = provider.digest().digestSync(clearText);

            assertEquals(sourceHash, decryptedHash);
            assertArrayEquals(sourceData, clearText.array());
        }

    }

    @Test
    @Order(225)
    @DisplayName("Encryption :: Cipher -> Sync Exceptions")
    public void testCryptoCipherSyncExceptions() throws Exception {

        try (final Cryptography provider = Cryptography.newDefaultInstance()) {
            final CipherTransformation noneTransformation =
                    new CipherTransformation(CipherAlgorithm.NONE, CipherMode.NONE, CipherPadding.NONE);

            final byte[] sourceData = new byte[100];
            final byte[] zeroLengthIv = new byte[0];

            final SecureRandom random = SecureRandom.getInstance("NativePRNGNonBlocking");
            random.nextBytes(sourceData);

            final KeyGenerator keyGenerator = KeyGenerator.getInstance(CipherAlgorithm.AES.keyAlgorithmName());
            keyGenerator.init(AES_KEY_SIZE, random);

            final SecretKey secretKey = keyGenerator.generateKey();


            assertThrows(CryptographyException.class, () -> provider.encryption().nonceSync(noneTransformation));

            try (final ByteArrayInputStream iStream = new ByteArrayInputStream(sourceData);
                 final ByteArrayOutputStream oStream = new ByteArrayOutputStream()) {
                assertThrows(CryptographyException.class,
                        () -> provider.encryption().encryptSync(secretKey, zeroLengthIv, iStream, oStream));

                assertThrows(CryptographyException.class,
                        () -> provider.encryption().decryptSync(secretKey, zeroLengthIv, iStream, oStream));
            }

            assertThrows(CryptographyException.class,
                    () -> provider.encryption().encryptSync(secretKey, zeroLengthIv, sourceData));

            assertThrows(CryptographyException.class,
                    () -> provider.encryption().decryptSync(secretKey, zeroLengthIv, sourceData));

            assertThrows(CryptographyException.class,
                    () -> provider.encryption().encryptSync(secretKey, zeroLengthIv, ByteBuffer.wrap(sourceData)));

            assertThrows(CryptographyException.class,
                    () -> provider.encryption().decryptSync(secretKey, zeroLengthIv, ByteBuffer.wrap(sourceData)));
        }

    }

    @ParameterizedTest
    @Order(75)
    @DisplayName("Encryption :: Cipher -> Sync Stream Encryption")
    @MethodSource("transformationSource")
    public void testCryptoCipherSyncStreamEncryption(CipherTransformation transformation,
                                                     @TempDir File tempDir) throws Exception {

        final boolean usingDefaults = Objects.equals(new CipherTransformation(), transformation);

        assertNotNull(tempDir);
        assertTrue(tempDir::exists);
        assertTrue(tempDir::isDirectory);

        final File encryptedFile = new File(tempDir, ENCRYPTED_LARGE_FILE_NAME);
        final File decryptedFile = new File(tempDir, DECRYPTED_LARGE_FILE_NAME);

        final ClassLoader classLoader = getClass().getClassLoader();

        final Hash sourceHash;

        try (final Cryptography provider = Cryptography.newDefaultInstance();
             final InputStream sourceStream = classLoader.getResourceAsStream(LARGE_FILE_NAME)) {

            assertNotNull(sourceStream);

            // Compute source hash
            sourceHash = provider.digest().digestSync(sourceStream);
            assertNotNull(sourceHash);
        }

        try (final Cryptography provider = Cryptography.newDefaultInstance();
             final InputStream sourceStream = classLoader.getResourceAsStream(LARGE_FILE_NAME)) {

            assertNotNull(sourceStream);

            // Find a secure random source
            final SecureRandom random = SecureRandom.getInstance("NativePRNGNonBlocking");

            // Setup OTP structures
            final byte[] iv = provider.encryption().nonceSync(transformation);

            final KeyGenerator keyGenerator = KeyGenerator.getInstance(CipherAlgorithm.AES.keyAlgorithmName());
            keyGenerator.init(AES_KEY_SIZE, random);

            final SecretKey secretKey = keyGenerator.generateKey();
            assertNotNull(secretKey);

            // Encrypt
            try (final FileOutputStream cipherStream = new FileOutputStream(encryptedFile)) {
                if (usingDefaults) {
                    provider.encryption().encryptSync(secretKey, iv, sourceStream, cipherStream);
                } else {
                    provider.encryption().encryptSync(transformation, secretKey, iv, sourceStream, cipherStream);
                }
            }

            // Decrypt
            try (final FileInputStream cipherStream = new FileInputStream(encryptedFile);
                 final FileOutputStream clearStream = new FileOutputStream(decryptedFile)) {
                if (usingDefaults) {
                    provider.encryption().decryptSync(secretKey, iv, cipherStream, clearStream);
                } else {
                    provider.encryption().decryptSync(transformation, secretKey, iv, cipherStream, clearStream);
                }
            }

            // Hash Decrypted Stream
            final Hash decryptedHash;
            try (final FileInputStream clearStream = new FileInputStream(decryptedFile)) {
                decryptedHash = provider.digest().digestSync(clearStream);
                assertNotNull(decryptedHash);
            }

            assertEquals(sourceHash, decryptedHash);
        }
    }

    @Test
    @Order(50)
    @DisplayName("Encryption :: CipherTransformation -> Basic")
    public void testCryptoCipherTransformationBasic() {
        final BouncyCastleProvider bcProv = new BouncyCastleProvider();
        final CipherTransformation noneTransform =
                new CipherTransformation(CipherAlgorithm.NONE, CipherMode.NONE, CipherPadding.NONE);

        final CipherTransformation defaultTransform = new CipherTransformation();

        final CipherTransformation cbcPkcs5Transform =
                new CipherTransformation(CipherAlgorithm.AES, CipherMode.CBC, CipherPadding.PKCS5);

        final CipherTransformation refCbcPkcs5Transform = cbcPkcs5Transform;

        final CipherTransformation aesAlgorithmOnly = new CipherTransformation(CipherAlgorithm.AES, null, null);

        final CipherTransformation altCbcPkcs5Transform =
                new CipherTransformation(CipherAlgorithm.AES, CipherMode.CBC, CipherPadding.PKCS5);

        // Constructor Tests
        assertThrows(IllegalArgumentException.class, () -> new CipherTransformation(null));

        // Cipher Instance Tests
        assertThrows(CryptographyException.class, noneTransform::instance);

        assertDoesNotThrow((ThrowingSupplier<Cipher>) defaultTransform::instance);
        assertDoesNotThrow((ThrowingSupplier<Cipher>) cbcPkcs5Transform::instance);
        assertDoesNotThrow((ThrowingSupplier<Cipher>) aesAlgorithmOnly::instance);

        assertThrows(CryptographyException.class, () -> defaultTransform.instance("NONE"));
        assertDoesNotThrow(() -> defaultTransform.instance("SunJCE"));
        assertDoesNotThrow(() -> defaultTransform.instance(bcProv));

        assertThrows(CryptographyException.class, () -> noneTransform.instance(bcProv));

        assertDoesNotThrow(() -> cbcPkcs5Transform.instance(bcProv));

        // Getter & Setter Tests
        assertEquals(CipherAlgorithm.AES, defaultTransform.getAlgorithm());
        assertEquals(CipherMode.GCM, defaultTransform.getMode());
        assertEquals(CipherPadding.NONE, defaultTransform.getPadding());

        assertThrows(IllegalArgumentException.class, () -> defaultTransform.setAlgorithm(null));

        defaultTransform.setAlgorithm(CipherAlgorithm.NONE);
        defaultTransform.setMode(CipherMode.ECB);
        defaultTransform.setPadding(CipherPadding.OAEP);

        assertEquals(CipherAlgorithm.NONE, defaultTransform.getAlgorithm());
        assertEquals(CipherMode.ECB, defaultTransform.getMode());
        assertEquals(CipherPadding.OAEP, defaultTransform.getPadding());

        defaultTransform.setAlgorithm(CipherAlgorithm.AES);
        defaultTransform.setMode(CipherMode.GCM);
        defaultTransform.setPadding(CipherPadding.NONE);

        // CompareTo Validation
        assertEquals(EQUAL, cbcPkcs5Transform.compareTo(altCbcPkcs5Transform));
        assertEquals(EQUAL, cbcPkcs5Transform.compareTo(refCbcPkcs5Transform));
        assertEquals(GREATER_THAN, cbcPkcs5Transform.compareTo(null));
        assertEquals(LESS_THAN, noneTransform.compareTo(defaultTransform));

        // toString/hashCode/equals Validations (using empty & actual hash values)
        assertNotNull(defaultTransform.toString());

        assertEquals(cbcPkcs5Transform, refCbcPkcs5Transform);
        assertEquals(cbcPkcs5Transform, altCbcPkcs5Transform);

        assertNotEquals(0, defaultTransform.hashCode());
        assertFalse(defaultTransform.equals(null));
    }
}
