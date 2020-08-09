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

package com.servercurio.fabric.lang;

import com.servercurio.fabric.security.Hash;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static com.servercurio.fabric.lang.Validators.throwIfArgumentIsEmpty;
import static com.servercurio.fabric.lang.Validators.throwIfArgumentIsNotExactSize;
import static com.servercurio.fabric.lang.Validators.throwIfArgumentIsNotPositive;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("Validators: General")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ValidatorTests {

    private static final String TEST_PARAM = "test";

    @Test
    @Order(25)
    @DisplayName("Validators :: Positive Integer")
    public void testValidatorsPositiveInteger() {
        assertThrows(IllegalArgumentException.class, () -> throwIfArgumentIsNotPositive(0, TEST_PARAM));
        assertThrows(IllegalArgumentException.class, () -> throwIfArgumentIsNotPositive((short) 0, TEST_PARAM));
        assertThrows(IllegalArgumentException.class, () -> throwIfArgumentIsNotPositive((byte) 0, TEST_PARAM));
        assertThrows(IllegalArgumentException.class, () -> throwIfArgumentIsNotPositive(0L, TEST_PARAM));
        assertThrows(IllegalArgumentException.class, () -> throwIfArgumentIsNotPositive(0.0F, TEST_PARAM));
        assertThrows(IllegalArgumentException.class, () -> throwIfArgumentIsNotPositive(0.0, TEST_PARAM));

        assertDoesNotThrow(() -> throwIfArgumentIsNotPositive(1, TEST_PARAM));
        assertDoesNotThrow(() -> throwIfArgumentIsNotPositive((short) 1, TEST_PARAM));
        assertDoesNotThrow(() -> throwIfArgumentIsNotPositive((byte) 1, TEST_PARAM));
        assertDoesNotThrow(() -> throwIfArgumentIsNotPositive(1L, TEST_PARAM));
        assertDoesNotThrow(() -> throwIfArgumentIsNotPositive(1.0F, TEST_PARAM));
        assertDoesNotThrow(() -> throwIfArgumentIsNotPositive(1.0, TEST_PARAM));
    }

    @Test
    @Order(50)
    @DisplayName("Validators :: Empty")
    public void testValidatorsEmpty() {
       assertThrows(IllegalArgumentException.class, () -> throwIfArgumentIsEmpty(StringConstants.EMPTY, TEST_PARAM));
       assertThrows(IllegalArgumentException.class, () -> throwIfArgumentIsEmpty(new Long[0], TEST_PARAM));

       assertDoesNotThrow(() -> throwIfArgumentIsEmpty(StringConstants.AMPERSAND, TEST_PARAM));
       assertDoesNotThrow(() -> throwIfArgumentIsEmpty(new Long[10], TEST_PARAM));
    }

    @Test
    @Order(75)
    @DisplayName("Validators :: Not Exact Size")
    public void testValidatorsNotExactSize() {
        assertThrows(IllegalArgumentException.class, () -> throwIfArgumentIsNotExactSize(new Long[5], 6, TEST_PARAM));

        assertDoesNotThrow(() -> throwIfArgumentIsNotExactSize(new Long[10], 10, TEST_PARAM));
    }
}
