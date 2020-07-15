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
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.SecureRandom;
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

import static com.servercurio.fabric.lang.ComparableConstants.EQUAL;
import static com.servercurio.fabric.lang.ComparableConstants.GREATER_THAN;
import static com.servercurio.fabric.lang.ComparableConstants.LESS_THAN;
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

    private static final String LARGE_FILE_NAME = "cbad3520af182b5d23b60412dff6ea5fa754c82c.bin";
    private static final String ENCRYPTED_LARGE_FILE_NAME = "cbad3520af182b5d23b60412dff6ea5fa754c82c.enc";
    private static final String DECRYPTED_LARGE_FILE_NAME = "cbad3520af182b5d23b60412dff6ea5fa754c82c.dec";

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

        assertEquals(1, CipherPadding.ISO10126.id());
        assertEquals("PKCS5Padding", CipherPadding.PKCS5.paddingName());
        assertEquals(CipherPadding.PKCS5, CipherPadding.valueOf("PKCS5"));
        assertEquals(CipherPadding.PKCS5, CipherPadding.valueOf(CipherPadding.PKCS5.id()));
        assertNull(CipherPadding.valueOf(-1));
    }

    @Test
    @Order(75)
    @DisplayName("Encryption :: Cipher -> Sync Stream Encryption")
    public void testCryptoCipherSyncStreamEncryption(@TempDir File tempDir) throws Exception {
        assertNotNull(tempDir);
        assertTrue(tempDir::exists);
        assertTrue(tempDir::isDirectory);

        final File encryptedFile = new File(tempDir, ENCRYPTED_LARGE_FILE_NAME);
        final File decryptedFile = new File(tempDir, DECRYPTED_LARGE_FILE_NAME);

        final ClassLoader classLoader = getClass().getClassLoader();

        Hash sourceHash;

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
            final SecureRandom random = provider.random();

            // Setup OTP structures
            final byte[] iv = provider.encryption().nonceSync();

            final KeyGenerator keyGenerator = KeyGenerator.getInstance(CipherAlgorithm.AES.keyAlgorithmName());
            keyGenerator.init(AES_KEY_SIZE, random);

            final SecretKey secretKey = keyGenerator.generateKey();
            assertNotNull(secretKey);

            // Encrypt
            try (final FileOutputStream cipherStream = new FileOutputStream(encryptedFile)) {
                provider.encryption().encryptSync(secretKey, iv, sourceStream, cipherStream);
            }

            // Decrypt
            try (final FileInputStream cipherStream = new FileInputStream(encryptedFile);
                 final FileOutputStream clearStream = new FileOutputStream(decryptedFile)) {
                provider.encryption().decryptSync(secretKey, iv, cipherStream, clearStream);
            }

            // Hash Decrypted Stream
            Hash decryptedHash;
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
        defaultTransform.setPadding(CipherPadding.ISO10126);

        assertEquals(CipherAlgorithm.NONE, defaultTransform.getAlgorithm());
        assertEquals(CipherMode.ECB, defaultTransform.getMode());
        assertEquals(CipherPadding.ISO10126, defaultTransform.getPadding());

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
