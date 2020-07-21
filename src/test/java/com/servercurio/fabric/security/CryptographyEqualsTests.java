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

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Cryptography: Secure Equals")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class CryptographyEqualsTests {

    @ParameterizedTest
    @Order(50)
    @DisplayName("Cryptography :: SecureEquals -> Basic Byte Array")
    @ValueSource(ints = {1, 5, 10, 76})
    public void testCryptoSecureEqualsByteArray(int length) throws Exception {
        try (final Cryptography crypto = Cryptography.newDefaultInstance()) {
            final Random random = new Random();

            final byte[] originalValue = new byte[length];
            random.nextBytes(originalValue);

            final byte[] copiedValue = Arrays.copyOf(originalValue, originalValue.length);
            final byte[] extraSizedValue = Arrays.copyOf(originalValue, originalValue.length + random.nextInt(10) + 1);

            assertTrue(crypto.secureEquals(originalValue, copiedValue));
            assertFalse(crypto.secureEquals(originalValue, extraSizedValue));
        }
    }

    @ParameterizedTest
    @Order(25)
    @DisplayName("Cryptography :: SecureEquals -> Basic Char Array")
    @ValueSource(ints = {1, 5, 10, 76})
    public void testCryptoSecureEqualsCharArray(int length) throws Exception {
        try (final Cryptography crypto = Cryptography.newDefaultInstance()) {
            final Random random = new Random();

            final char[] originalValue = new char[length];

            for (int i = 0; i < originalValue.length; i++) {
                originalValue[i] = (char)random.nextInt();
            }

            final char[] copiedValue = Arrays.copyOf(originalValue, originalValue.length);
            final char[] extraSizedValue = Arrays.copyOf(originalValue, originalValue.length + random.nextInt(10) + 1);

            assertTrue(crypto.secureEquals(originalValue, copiedValue));
            assertFalse(crypto.secureEquals(originalValue, extraSizedValue));
        }
    }

    @ParameterizedTest
    @Order(75)
    @DisplayName("Cryptography :: SecureEquals -> Basic Int Array")
    @ValueSource(ints = {1, 5, 10, 76})
    public void testCryptoSecureEqualsIntArray(int length) throws Exception {
        try (final Cryptography crypto = Cryptography.newDefaultInstance()) {
            final Random random = new Random();

            final int[] originalValue = new int[length];

            for (int i = 0; i < originalValue.length; i++) {
                originalValue[i] = random.nextInt();
            }

            final int[] copiedValue = Arrays.copyOf(originalValue, originalValue.length);
            final int[] extraSizedValue = Arrays.copyOf(originalValue, originalValue.length + random.nextInt(10) + 1);

            assertTrue(crypto.secureEquals(originalValue, copiedValue));
            assertFalse(crypto.secureEquals(originalValue, extraSizedValue));
        }
    }

    @ParameterizedTest
    @Order(100)
    @DisplayName("Cryptography :: SecureEquals -> Basic Long Array")
    @ValueSource(ints = {1, 5, 10, 76})
    public void testCryptoSecureEqualsLongArray(int length) throws Exception {
        try (final Cryptography crypto = Cryptography.newDefaultInstance()) {
            final Random random = new Random();

            final long[] originalValue = new long[length];

            for (int i = 0; i < originalValue.length; i++) {
                originalValue[i] = random.nextLong();
            }

            final long[] copiedValue = Arrays.copyOf(originalValue, originalValue.length);
            final long[] extraSizedValue = Arrays.copyOf(originalValue, originalValue.length + random.nextInt(10) + 1);

            assertTrue(crypto.secureEquals(originalValue, copiedValue));
            assertFalse(crypto.secureEquals(originalValue, extraSizedValue));
        }
    }
}
