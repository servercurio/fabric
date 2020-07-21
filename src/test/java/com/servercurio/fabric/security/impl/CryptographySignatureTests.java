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

import com.servercurio.fabric.security.Cryptography;
import com.servercurio.fabric.security.CryptographyException;
import com.servercurio.fabric.security.HashAlgorithm;
import com.servercurio.fabric.security.MockHash;
import com.servercurio.fabric.security.Seal;
import com.servercurio.fabric.security.SignatureAlgorithm;
import com.servercurio.fabric.security.spi.SignatureProvider;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Cryptography: Signatures")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class CryptographySignatureTests {

    private static final String LARGE_FILE_NAME = "cbad3520af182b5d23b60412dff6ea5fa754c82c.bin";

    private static final byte[] IN_MEMORY_DATA;
    private static final MockHash IN_MEMORY_DATA_KNOWN_HASH;

    private static final MockHash WELL_KNOWN_HASH;
    private static final MockHash ALTERNATE_WELL_KNOWN_HASH;

    private static final byte[] PUBLIC_KEY_BYTES = Base64.getDecoder()
                                                         .decode("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArbJ4V9ID6Uu/bDO2BlJ03fMrUMsdcbCCXJq9ihfHERXqvRDp9rJvBCoY/fpUHykj0a3Z5bPE9ZtUOcfO7OLEWLPV/S8Ls2rlLRPL+EmF/eekvbRJVopIaUBG9+ayjDwwGWNguFYeU2KbFHqytshk6ob/1//cOq5hn30bzoZZTvz0LM+xTzzWWWUA5cjqSeBWrX1kJXadMws2kdyE2HjUMVSwHwXKmzYvXgp6TGjT3U4FfvJFFOq1LLdTAOjYDSok7hnhpnjGLzGiDMxTlN3pBRAIA0Esv8YX5Hjokmb+LNus4RawlgWOXT7VeiqJEBZxdYM0RxACdfVxB+/4yEhuNwIDAQAB");

    private static final byte[] PRIVATE_KEY_BYTES = Base64.getDecoder()
                                                          .decode("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCtsnhX0gPpS79sM7YGUnTd8ytQyx1xsIJcmr2KF8cRFeq9EOn2sm8EKhj9+lQfKSPRrdnls8T1m1Q5x87s4sRYs9X9LwuzauUtE8v4SYX956S9tElWikhpQEb35rKMPDAZY2C4Vh5TYpsUerK2yGTqhv/X/9w6rmGffRvOhllO/PQsz7FPPNZZZQDlyOpJ4FatfWQldp0zCzaR3ITYeNQxVLAfBcqbNi9eCnpMaNPdTgV+8kUU6rUst1MA6NgNKiTuGeGmeMYvMaIMzFOU3ekFEAgDQSy/xhfkeOiSZv4s26zhFrCWBY5dPtV6KokQFnF1gzRHEAJ19XEH7/jISG43AgMBAAECggEAbylmpx1671VQ3piBh65BqMG1GPHEmDvUUhud7cCl36NdJT6r3Pv43Htsny4TpBWaHNjcOItCI8UStB/Rp/zAl9wPuQbgwCRLIvwmb3HuVL5oyheVT9MT4HgIcyKrZeAnEDhvb8l9gvP6N7MGqL+7BfT7y2qtsMhlJcLVhuioQ0nFLHlW07NWu183YO2/t5XwdWY7aukJzD2C7ePtAIBr0OmjUAkNCX/EQPETJi+eJBPgZaXIFMnu24IKjf/YufGvUAEWSzbeEGgCaZnAKBesspZmyKpaTj1YkhCF8tH3EXcPvxmddRYORAr1aYS9IgT1C9b+AlpRXGz+vpMsxiUbAQKBgQDg1GgTI+QM5V+4krA4mcZ+gR8UCbYHOhADl7KVzxCW+8kuicHU1g6H6TXAnYFcUXTlQcaqGyGZycbUhttSkqnd3oUh1j9gC9aaLxLvYm27kUDsNTT7KIDSsnQv+rPxzD8ceyjDJOqdvdGVYe0H1oFw+KrvJChQowthduODGdzM9wKBgQDFx0flL2xNxsADdk7H5agYoc+arRDLwBMqzUvwG78Bw3VilzRHfrBzdgToONrE9HDDNbLHYe0e6vXUCahOU7pjl198onOrQq3dXNBReNCDVFHQ/efYt8flYjTRYKH1cXs36x2FP3kiu7dESoV2ifRfDZMg7vLal4LglUwc2ktYwQKBgAidOsuY8XDpDOzWefgBNFC+g8FRye6m89wfYNFKmLkgNooY7xtHhFECx3N01XMDD/aEuabk2Tm6OGsGK7sTMXz1vKYaPl1gtr07ln8jh07LdvBV7Yy99YmdGsSH14MpLzXZJiur621Vy4Tstpc5ScZZULtO6FiGlrYKRxdL02DrAoGBAL8wyCWb1HzTVyeBpOLE9dzp/4EtMIFm6qCD2ZcBm4Ie60klllpO9FCJlHDRFVs0WhW7wVnRJqKuzHnv5A3kDtjbqmkXue2jBeRqJs+7lQZ/6p+38/qintD2QMzvN2HIFC+YT+9Rzs5u3NldmOtgrSV+P+6kT4xUzyY/7VYvCIuBAoGAfWi1MRI3G2SZtyxeeLuRNqzicS54B8zU0Xko31ik6wPowPp6pA4NJL6SSX5zzokpVrsySonI1yCCI96JmRLar4rrj7C5fHNKaKCSTK9sergcz1zxOtV0mGQggMEv26C3nxcdx3Jzok4JJOdxOkzF0bZjJRXoLM25FqkxRtVfwvU=");

    static {
        WELL_KNOWN_HASH = new MockHash(HashAlgorithm.SHA_384,
                Base64.getDecoder()
                      .decode("pKA/NF3xZhm+DOBne5MhXxq41eSYHyom/bAPvyCrrDNT8vt5eODhhtWG7LpQlHEE"));

        ALTERNATE_WELL_KNOWN_HASH = new MockHash(HashAlgorithm.SHA_384,
                Base64.getDecoder()
                      .decode("RXzuRQUHOT5zssgipY+PLujP4FrmQJQzVAvni+s52GcwtzkAnq+nRwwmW7noRqvx"));

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
    }

    @Test
    @Order(20)
    @DisplayName("Signature :: RSA_SHA_384 -> Basic Seal")
    public void testCryptoRsaSha384BasicSeal() throws Exception {
        try (final Cryptography provider = Cryptography.newDefaultInstance()) {

            final byte[] invalidLengthHash = new byte[0];
            final byte[] validHashBytes = WELL_KNOWN_HASH.getValue();
            final byte[] zeroBytes = new byte[HashAlgorithm.SHA_384.bytes()];

            // Constructor Exceptions
            assertThrows(IllegalArgumentException.class, () -> new Seal(null, validHashBytes));
            assertThrows(IllegalArgumentException.class, () -> new Seal(SignatureAlgorithm.RSA_SHA_384, null));
            assertThrows(IllegalArgumentException.class,
                    () -> new Seal(SignatureAlgorithm.RSA_SHA_384, invalidLengthHash));
            assertThrows(IllegalArgumentException.class, () -> new Seal(null));

            // Constructor Copies
            final Seal emptyCopy = new Seal(Seal.EMPTY);
            final Seal emptyRef = Seal.EMPTY;
            final Seal validOriginal = new Seal(SignatureAlgorithm.RSA_SHA_384, WELL_KNOWN_HASH.getValue());
            final Seal validCopy = new Seal(validOriginal);
            final Seal zeroSeal = new Seal(SignatureAlgorithm.RSA_SHA_384, zeroBytes);

            // isEmpty Validations
            assertTrue(zeroSeal::isEmpty);
            assertTrue(emptyCopy::isEmpty);
            assertFalse(validCopy::isEmpty);

            // CompareTo Validation
            assertFalse(zeroSeal.equals(WELL_KNOWN_HASH));
            assertEquals(Seal.EMPTY, emptyRef);
            assertNotEquals(null, Seal.EMPTY);

            assertEquals(EQUAL, Seal.EMPTY.compareTo(emptyCopy));
            assertEquals(EQUAL, Seal.EMPTY.compareTo(Seal.EMPTY));
            assertEquals(GREATER_THAN, Seal.EMPTY.compareTo(null));

            // toString/hashCode/equals Validations (using empty & actual hash values)
            assertNotNull(Seal.EMPTY.toString());
            assertNotEquals(0, validCopy.hashCode());

            assertEquals(Seal.EMPTY, emptyCopy);
            assertEquals(validOriginal, validCopy);
        }
    }

    @Test
    @Order(75)
    @DisplayName("Signature :: RSA_SHA_384 -> Async Byte Buffer")
    public void testCryptoSignSha384RsaAsyncByteBuffer() throws Exception {
        try (final Cryptography crypto = Cryptography.newDefaultInstance()) {
            final SignatureProvider provider = crypto.signature();

            final ByteBuffer defaultBuffer = ByteBuffer.allocateDirect(IN_MEMORY_DATA.length);
            defaultBuffer.put(IN_MEMORY_DATA).rewind();

            final ByteBuffer explicitBuffer = ByteBuffer.allocateDirect(IN_MEMORY_DATA.length);
            explicitBuffer.put(IN_MEMORY_DATA).rewind();

            final KeyFactory keyFactory = KeyFactory.getInstance(SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final KeySpec privateKeySpec =
                    new PKCS8EncodedKeySpec(PRIVATE_KEY_BYTES, SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final KeySpec publicKeySpec =
                    new X509EncodedKeySpec(PUBLIC_KEY_BYTES, SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            final PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            final Future<Seal> defaultSealFuture = provider.signAsync(privateKey, defaultBuffer);
            final Future<Seal> explicitSealFuture =
                    provider.signAsync(SignatureAlgorithm.RSA_SHA_384, privateKey, explicitBuffer);

            final Seal defaultSeal = defaultSealFuture.get();
            final Seal explicitSeal = explicitSealFuture.get();

            assertEquals(defaultSeal, explicitSeal);
            defaultBuffer.rewind();
            explicitBuffer.rewind();

            assertTrue(provider.verifyAsync(defaultSeal, publicKey, defaultBuffer).get());
            assertTrue(provider.verifyAsync(explicitSeal, publicKey, explicitBuffer).get());
        }
    }

    @Test
    @Order(275)
    @DisplayName("Signature :: RSA_SHA_384 -> Async Exceptions")
    public void testCryptoSignSha384RsaAsyncExceptions() throws Exception {
        try (final Cryptography crypto = Cryptography.newDefaultInstance()) {
            final SignatureProvider provider = crypto.signature();
            final ClassLoader classLoader = getClass().getClassLoader();


            final KeyFactory keyFactory = KeyFactory.getInstance(SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final KeySpec privateKeySpec =
                    new PKCS8EncodedKeySpec(PRIVATE_KEY_BYTES, SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final KeySpec publicKeySpec =
                    new X509EncodedKeySpec(PUBLIC_KEY_BYTES, SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            final PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);


            final Seal defaultSeal;

            try (final InputStream stream = classLoader.getResourceAsStream(LARGE_FILE_NAME)) {
                defaultSeal = provider.signSync(privateKey, stream);
            }

            try (final InputStream stream = classLoader.getResourceAsStream(LARGE_FILE_NAME)) {
                assertThrows(ExecutionException.class, () -> provider.signAsync(null, stream).get());
            }

            try (final InputStream stream = classLoader.getResourceAsStream(LARGE_FILE_NAME)) {
                assertThrows(ExecutionException.class, () -> provider.verifyAsync(defaultSeal, null, stream).get());
            }

            assertThrows(ExecutionException.class, () -> provider.signAsync(null, IN_MEMORY_DATA).get());
            assertThrows(ExecutionException.class,
                    () -> provider.verifyAsync(defaultSeal, null, IN_MEMORY_DATA).get());

            assertThrows(ExecutionException.class,
                    () -> provider.signAsync(null, ByteBuffer.wrap(IN_MEMORY_DATA)).get());
            assertThrows(ExecutionException.class,
                    () -> provider.verifyAsync(defaultSeal, null, ByteBuffer.wrap(IN_MEMORY_DATA)).get());

            assertThrows(ExecutionException.class,
                    () -> provider.signAsync(null, WELL_KNOWN_HASH, ALTERNATE_WELL_KNOWN_HASH).get());
            assertThrows(ExecutionException.class,
                    () -> provider.verifyAsync(defaultSeal, null, WELL_KNOWN_HASH, ALTERNATE_WELL_KNOWN_HASH).get());
        }
    }

    @Test
    @Order(175)
    @DisplayName("Signature :: RSA_SHA_384 -> Async Hash of Hashes")
    public void testCryptoSignSha384RsaAsyncHashOfHashes() throws Exception {
        try (final Cryptography crypto = Cryptography.newDefaultInstance()) {
            final SignatureProvider provider = crypto.signature();

            final KeyFactory keyFactory = KeyFactory.getInstance(SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final KeySpec privateKeySpec =
                    new PKCS8EncodedKeySpec(PRIVATE_KEY_BYTES, SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final KeySpec publicKeySpec =
                    new X509EncodedKeySpec(PUBLIC_KEY_BYTES, SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            final PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            final Future<Seal> defaultSealFuture =
                    provider.signAsync(privateKey, WELL_KNOWN_HASH, ALTERNATE_WELL_KNOWN_HASH);
            final Future<Seal> explicitSealFuture =
                    provider.signAsync(SignatureAlgorithm.RSA_SHA_384, privateKey, WELL_KNOWN_HASH,
                            ALTERNATE_WELL_KNOWN_HASH);
            final Future<Seal> nullLeftFuture = provider.signAsync(privateKey, null, ALTERNATE_WELL_KNOWN_HASH);
            final Future<Seal> nullRightFuture = provider.signAsync(privateKey, WELL_KNOWN_HASH, null);


            final Seal defaultSeal = defaultSealFuture.get();
            final Seal explicitSeal = explicitSealFuture.get();
            final Seal nullLeftHashOfHashes = nullLeftFuture.get();
            final Seal nullRightHashOfHashes = nullRightFuture.get();

            assertEquals(defaultSeal, explicitSeal);

            assertTrue(provider.verifyAsync(defaultSeal, publicKey, WELL_KNOWN_HASH, ALTERNATE_WELL_KNOWN_HASH).get());
            assertTrue(provider.verifyAsync(explicitSeal, publicKey, WELL_KNOWN_HASH, ALTERNATE_WELL_KNOWN_HASH).get());

            assertTrue(provider.verifyAsync(nullLeftHashOfHashes, publicKey, null, ALTERNATE_WELL_KNOWN_HASH).get());
            assertTrue(provider.verifyAsync(nullRightHashOfHashes, publicKey, WELL_KNOWN_HASH, null).get());
        }
    }

    @Test
    @Order(125)
    @DisplayName("Signature :: RSA_SHA_384 -> Async In Memory Data")
    public void testCryptoSignSha384RsaAsyncInMemoryData() throws Exception {
        try (final Cryptography crypto = Cryptography.newDefaultInstance()) {
            final SignatureProvider provider = crypto.signature();

            final KeyFactory keyFactory = KeyFactory.getInstance(SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final KeySpec privateKeySpec =
                    new PKCS8EncodedKeySpec(PRIVATE_KEY_BYTES, SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final KeySpec publicKeySpec =
                    new X509EncodedKeySpec(PUBLIC_KEY_BYTES, SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            final PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            final Future<Seal> defaultSealFuture = provider.signAsync(privateKey, IN_MEMORY_DATA);
            final Future<Seal> explicitSealFuture =
                    provider.signAsync(SignatureAlgorithm.RSA_SHA_384, privateKey, IN_MEMORY_DATA);

            final Seal defaultSeal = defaultSealFuture.get();
            final Seal explicitSeal = explicitSealFuture.get();

            assertEquals(defaultSeal, explicitSeal);

            assertTrue(provider.verifyAsync(defaultSeal, publicKey, IN_MEMORY_DATA).get());
            assertTrue(provider.verifyAsync(explicitSeal, publicKey, IN_MEMORY_DATA).get());
        }
    }

    @Test
    @Order(225)
    @DisplayName("Signature :: RSA_SHA_384 -> Async Large File")
    public void testCryptoSignSha384RsaAsyncLargeFile() throws Exception {
        try (final Cryptography crypto = Cryptography.newDefaultInstance()) {
            final SignatureProvider provider = crypto.signature();
            final ClassLoader classLoader = getClass().getClassLoader();


            final KeyFactory keyFactory = KeyFactory.getInstance(SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final KeySpec privateKeySpec =
                    new PKCS8EncodedKeySpec(PRIVATE_KEY_BYTES, SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final KeySpec publicKeySpec =
                    new X509EncodedKeySpec(PUBLIC_KEY_BYTES, SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            final PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            final Seal defaultSeal;
            final Seal explicitSeal;

            try (final InputStream stream = classLoader.getResourceAsStream(LARGE_FILE_NAME)) {
                defaultSeal = provider.signAsync(privateKey, stream).get();
                assertNotNull(defaultSeal);
            }

            try (final InputStream stream = classLoader.getResourceAsStream(LARGE_FILE_NAME)) {
                explicitSeal = provider.signAsync(SignatureAlgorithm.RSA_SHA_384, privateKey, stream).get();
                assertNotNull(explicitSeal);
            }

            assertEquals(defaultSeal, explicitSeal);

            try (final InputStream stream = classLoader.getResourceAsStream(LARGE_FILE_NAME)) {
                assertTrue(provider.verifyAsync(defaultSeal, publicKey, stream).get());
            }

            try (final InputStream stream = classLoader.getResourceAsStream(LARGE_FILE_NAME)) {
                assertTrue(provider.verifyAsync(explicitSeal, publicKey, stream).get());
            }
        }
    }

    @Test
    @Order(50)
    @DisplayName("Signature :: RSA_SHA_384 -> Sync Byte Buffer")
    public void testCryptoSignSha384RsaSyncByteBuffer() throws Exception {
        try (final Cryptography crypto = Cryptography.newDefaultInstance()) {
            final SignatureProvider provider = crypto.signature();

            final ByteBuffer defaultBuffer = ByteBuffer.allocateDirect(IN_MEMORY_DATA.length);
            defaultBuffer.put(IN_MEMORY_DATA).rewind();

            final ByteBuffer explicitBuffer = ByteBuffer.allocateDirect(IN_MEMORY_DATA.length);
            explicitBuffer.put(IN_MEMORY_DATA).rewind();

            final KeyFactory keyFactory = KeyFactory.getInstance(SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final KeySpec privateKeySpec =
                    new PKCS8EncodedKeySpec(PRIVATE_KEY_BYTES, SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final KeySpec publicKeySpec =
                    new X509EncodedKeySpec(PUBLIC_KEY_BYTES, SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            final PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            final Seal defaultSeal = provider.signSync(privateKey, defaultBuffer);
            final Seal explicitSeal = provider.signSync(SignatureAlgorithm.RSA_SHA_384, privateKey, explicitBuffer);

            assertEquals(defaultSeal, explicitSeal);
            defaultBuffer.rewind();
            explicitBuffer.rewind();

            assertTrue(provider.verifySync(defaultSeal, publicKey, defaultBuffer));
            assertTrue(provider.verifySync(explicitSeal, publicKey, explicitBuffer));
        }
    }

    @Test
    @Order(250)
    @DisplayName("Signature :: RSA_SHA_384 -> Sync Exceptions")
    public void testCryptoSignSha384RsaSyncExceptions() throws Exception {
        try (final Cryptography crypto = Cryptography.newDefaultInstance()) {
            final SignatureProvider provider = crypto.signature();
            final ClassLoader classLoader = getClass().getClassLoader();


            final KeyFactory keyFactory = KeyFactory.getInstance(SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final KeySpec privateKeySpec =
                    new PKCS8EncodedKeySpec(PRIVATE_KEY_BYTES, SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final KeySpec publicKeySpec =
                    new X509EncodedKeySpec(PUBLIC_KEY_BYTES, SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            final PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);


            final Seal defaultSeal;

            try (final InputStream stream = classLoader.getResourceAsStream(LARGE_FILE_NAME)) {
                defaultSeal = provider.signSync(privateKey, stream);
            }

            try (final InputStream stream = classLoader.getResourceAsStream(LARGE_FILE_NAME)) {
                assertThrows(CryptographyException.class, () -> provider.signSync(null, stream));
            }

            try (final InputStream stream = classLoader.getResourceAsStream(LARGE_FILE_NAME)) {
                assertThrows(CryptographyException.class, () -> provider.verifySync(defaultSeal, null, stream));
            }

            assertThrows(CryptographyException.class, () -> provider.signSync(null, IN_MEMORY_DATA));
            assertThrows(CryptographyException.class, () -> provider.verifySync(defaultSeal, null, IN_MEMORY_DATA));

            assertThrows(CryptographyException.class, () -> provider.signSync(null, ByteBuffer.wrap(IN_MEMORY_DATA)));
            assertThrows(CryptographyException.class,
                    () -> provider.verifySync(defaultSeal, null, ByteBuffer.wrap(IN_MEMORY_DATA)));

            assertThrows(CryptographyException.class,
                    () -> provider.signSync(null, WELL_KNOWN_HASH, ALTERNATE_WELL_KNOWN_HASH));
            assertThrows(CryptographyException.class,
                    () -> provider.verifySync(defaultSeal, null, WELL_KNOWN_HASH, ALTERNATE_WELL_KNOWN_HASH));
        }
    }

    @Test
    @Order(150)
    @DisplayName("Signature :: RSA_SHA_384 -> Sync Hash Of Hashes")
    public void testCryptoSignSha384RsaSyncHashOfHashes() throws Exception {
        try (final Cryptography crypto = Cryptography.newDefaultInstance()) {
            final SignatureProvider provider = crypto.signature();

            final KeyFactory keyFactory = KeyFactory.getInstance(SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final KeySpec privateKeySpec =
                    new PKCS8EncodedKeySpec(PRIVATE_KEY_BYTES, SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final KeySpec publicKeySpec =
                    new X509EncodedKeySpec(PUBLIC_KEY_BYTES, SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            final PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            final Seal defaultSeal = provider.signSync(privateKey, WELL_KNOWN_HASH, ALTERNATE_WELL_KNOWN_HASH);
            final Seal explicitSeal = provider.signSync(SignatureAlgorithm.RSA_SHA_384, privateKey, WELL_KNOWN_HASH,
                    ALTERNATE_WELL_KNOWN_HASH);

            final Seal nullLeftHashOfHashes = provider.signSync(privateKey, null, ALTERNATE_WELL_KNOWN_HASH);
            final Seal nullRightHashOfHashes = provider.signSync(privateKey, WELL_KNOWN_HASH, null);

            assertEquals(defaultSeal, explicitSeal);

            assertTrue(provider.verifySync(defaultSeal, publicKey, WELL_KNOWN_HASH, ALTERNATE_WELL_KNOWN_HASH));
            assertTrue(provider.verifySync(explicitSeal, publicKey, WELL_KNOWN_HASH, ALTERNATE_WELL_KNOWN_HASH));

            assertTrue(provider.verifySync(nullLeftHashOfHashes, publicKey, null, ALTERNATE_WELL_KNOWN_HASH));
            assertTrue(provider.verifySync(nullRightHashOfHashes, publicKey, WELL_KNOWN_HASH, null));
        }
    }

    @Test
    @Order(100)
    @DisplayName("Signature :: RSA_SHA_384 -> Sync In Memory Data")
    public void testCryptoSignSha384RsaSyncInMemoryData() throws Exception {
        try (final Cryptography crypto = Cryptography.newDefaultInstance()) {
            final SignatureProvider provider = crypto.signature();

            final KeyFactory keyFactory = KeyFactory.getInstance(SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final KeySpec privateKeySpec =
                    new PKCS8EncodedKeySpec(PRIVATE_KEY_BYTES, SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final KeySpec publicKeySpec =
                    new X509EncodedKeySpec(PUBLIC_KEY_BYTES, SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            final PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            final Seal defaultSeal = provider.signSync(privateKey, IN_MEMORY_DATA);
            final Seal explicitSeal = provider.signSync(SignatureAlgorithm.RSA_SHA_384, privateKey, IN_MEMORY_DATA);

            assertEquals(defaultSeal, explicitSeal);

            assertTrue(provider.verifySync(defaultSeal, publicKey, IN_MEMORY_DATA));
            assertTrue(provider.verifySync(explicitSeal, publicKey, IN_MEMORY_DATA));
        }
    }

    @Test
    @Order(200)
    @DisplayName("Signature :: RSA_SHA_384 -> Sync Large File")
    public void testCryptoSignSha384RsaSyncLargeFile() throws Exception {
        try (final Cryptography crypto = Cryptography.newDefaultInstance()) {
            final SignatureProvider provider = crypto.signature();
            final ClassLoader classLoader = getClass().getClassLoader();


            final KeyFactory keyFactory = KeyFactory.getInstance(SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final KeySpec privateKeySpec =
                    new PKCS8EncodedKeySpec(PRIVATE_KEY_BYTES, SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final KeySpec publicKeySpec =
                    new X509EncodedKeySpec(PUBLIC_KEY_BYTES, SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());

            final PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            final PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

            final Seal defaultSeal;
            final Seal explicitSeal;

            try (final InputStream stream = classLoader.getResourceAsStream(LARGE_FILE_NAME)) {
                defaultSeal = provider.signSync(privateKey, stream);
                assertNotNull(defaultSeal);
            }

            try (final InputStream stream = classLoader.getResourceAsStream(LARGE_FILE_NAME)) {
                explicitSeal = provider.signSync(SignatureAlgorithm.RSA_SHA_384, privateKey, stream);
                assertNotNull(explicitSeal);
            }

            assertEquals(defaultSeal, explicitSeal);

            try (final InputStream stream = classLoader.getResourceAsStream(LARGE_FILE_NAME)) {
                assertTrue(provider.verifySync(defaultSeal, publicKey, stream));
            }

            try (final InputStream stream = classLoader.getResourceAsStream(LARGE_FILE_NAME)) {
                assertTrue(provider.verifySync(explicitSeal, publicKey, stream));
            }
        }
    }

    @Test
    @Order(25)
    @DisplayName("Signature :: SignatureAlgorithm -> Basic Enum")
    public void testCryptoSignatureAlgorithmBasicEnum() {
        final BouncyCastleProvider bcProv = new BouncyCastleProvider();

        assertEquals("RSA", SignatureAlgorithm.RSA_SHA_384.keyAlgorithmName());
        assertEquals(SignatureAlgorithm.RSA_SHA_384, SignatureAlgorithm.valueOf("RSA_SHA_384"));
        assertEquals(SignatureAlgorithm.RSA_SHA_384, SignatureAlgorithm.valueOf(SignatureAlgorithm.RSA_SHA_384.id()));
        assertEquals("SHA384withRSA", SignatureAlgorithm.RSA_SHA_384.algorithmName());

        assertNull(SignatureAlgorithm.valueOf(-1));

        assertThrows(CryptographyException.class, SignatureAlgorithm.NONE::instance);
        assertThrows(CryptographyException.class, () -> SignatureAlgorithm.NONE.instance(bcProv));
        assertThrows(CryptographyException.class, () -> SignatureAlgorithm.RSA_SHA_384.instance("INVALID"));
    }
}
