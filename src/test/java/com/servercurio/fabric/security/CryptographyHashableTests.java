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

import java.util.Base64;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("Cryptography: Hashable")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class CryptographyHashableTests {

    private static final byte[] IN_MEMORY_DATA;
    private static final MockHash IN_MEMORY_DATA_KNOWN_HASH;

    static {
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

    }

    @Test
    @Order(100)
    @DisplayName("Hashable :: SHA_384 -> Basic Hashable")
    public void testCryptoSha384BasicHashable() {
        final Cryptography crypto = Cryptography.newDefaultInstance();
        final MockHashable singleArgCtorHashable = new MockHashable(IN_MEMORY_DATA);
        final MockHashable twoArgCtorHashable = new MockHashable(HashAlgorithm.SHA_384, IN_MEMORY_DATA);
        final MockHashable threeArgCtorHashable =
                new MockHashable(HashAlgorithm.SHA_384, crypto, IN_MEMORY_DATA);

        // Basic getter checks
        assertEquals(HashAlgorithm.SHA_384, singleArgCtorHashable.getAlgorithm());
        assertEquals(crypto, threeArgCtorHashable.getCryptography());

        assertThrows(IllegalArgumentException.class, () -> new MockHashable(null, IN_MEMORY_DATA));
        assertThrows(IllegalArgumentException.class,
                     () -> new MockHashable(HashAlgorithm.SHA_384, null, IN_MEMORY_DATA));

        assertEquals(IN_MEMORY_DATA_KNOWN_HASH, singleArgCtorHashable.getHash());

        // Check the hash, set same hash, and check it again
        assertEquals(IN_MEMORY_DATA_KNOWN_HASH, twoArgCtorHashable.getHash());
        twoArgCtorHashable.setHash(twoArgCtorHashable.getHash());
        assertEquals(IN_MEMORY_DATA_KNOWN_HASH, twoArgCtorHashable.getHash());


        // Check it twice to double check caching
        assertEquals(IN_MEMORY_DATA_KNOWN_HASH, threeArgCtorHashable.getHash());
        assertEquals(IN_MEMORY_DATA_KNOWN_HASH, threeArgCtorHashable.getHash());

    }

}
