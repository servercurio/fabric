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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static com.servercurio.fabric.lang.Validators.throwIfArgIsNotPositiveOrZero;
import static com.servercurio.fabric.lang.Validators.throwIfArgumentIsEmpty;
import static com.servercurio.fabric.lang.Validators.throwIfArgIsNotExactLength;
import static com.servercurio.fabric.lang.Validators.throwIfArgIsNotPositive;
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
        assertThrows(IllegalArgumentException.class, () -> throwIfArgIsNotPositive(0, TEST_PARAM));
        assertThrows(IllegalArgumentException.class, () -> throwIfArgIsNotPositive((short) 0, TEST_PARAM));
        assertThrows(IllegalArgumentException.class, () -> throwIfArgIsNotPositive((byte) 0, TEST_PARAM));
        assertThrows(IllegalArgumentException.class, () -> throwIfArgIsNotPositive(0L, TEST_PARAM));
        assertThrows(IllegalArgumentException.class, () -> throwIfArgIsNotPositive(0.0F, TEST_PARAM));
        assertThrows(IllegalArgumentException.class, () -> throwIfArgIsNotPositive(0.0, TEST_PARAM));

        assertDoesNotThrow(() -> throwIfArgIsNotPositive(1, TEST_PARAM));
        assertDoesNotThrow(() -> throwIfArgIsNotPositive((short) 1, TEST_PARAM));
        assertDoesNotThrow(() -> throwIfArgIsNotPositive((byte) 1, TEST_PARAM));
        assertDoesNotThrow(() -> throwIfArgIsNotPositive(1L, TEST_PARAM));
        assertDoesNotThrow(() -> throwIfArgIsNotPositive(1.0F, TEST_PARAM));
        assertDoesNotThrow(() -> throwIfArgIsNotPositive(1.0, TEST_PARAM));
    }

    @Test
    @Order(75)
    @DisplayName("Validators :: Empty")
    public void testValidatorsEmpty() {
       assertThrows(IllegalArgumentException.class, () -> throwIfArgumentIsEmpty(StringConstants.EMPTY, TEST_PARAM));
       assertThrows(IllegalArgumentException.class, () -> throwIfArgumentIsEmpty(new Long[0], TEST_PARAM));

       assertDoesNotThrow(() -> throwIfArgumentIsEmpty(StringConstants.AMPERSAND, TEST_PARAM));
       assertDoesNotThrow(() -> throwIfArgumentIsEmpty(new Long[10], TEST_PARAM));
    }

    @Test
    @Order(100)
    @DisplayName("Validators :: Not Exact Length")
    public void testValidatorsNotExactLength() {
        assertThrows(IllegalArgumentException.class, () -> throwIfArgIsNotExactLength(new Long[5], 6, TEST_PARAM));
        assertThrows(IllegalArgumentException.class, () -> throwIfArgIsNotExactLength(TEST_PARAM, 6, TEST_PARAM));

        assertDoesNotThrow(() -> throwIfArgIsNotExactLength(new Long[10], 10, TEST_PARAM));
        assertDoesNotThrow(() -> throwIfArgIsNotExactLength(TEST_PARAM, 4, TEST_PARAM));
    }

    @Test
    @Order(50)
    @DisplayName("Validators :: Positive or Zero Integer")
    public void testValidatorsPositiveOrZeroInteger() {
        assertThrows(IllegalArgumentException.class, () -> throwIfArgIsNotPositiveOrZero(-1, TEST_PARAM));
        assertThrows(IllegalArgumentException.class, () -> throwIfArgIsNotPositiveOrZero((short) -1, TEST_PARAM));
        assertThrows(IllegalArgumentException.class, () -> throwIfArgIsNotPositiveOrZero((byte) -1, TEST_PARAM));
        assertThrows(IllegalArgumentException.class, () -> throwIfArgIsNotPositiveOrZero(-1L, TEST_PARAM));
        assertThrows(IllegalArgumentException.class, () -> throwIfArgIsNotPositiveOrZero(-0.03F, TEST_PARAM));
        assertThrows(IllegalArgumentException.class, () -> throwIfArgIsNotPositiveOrZero(-0.0001, TEST_PARAM));

        assertDoesNotThrow(() -> throwIfArgIsNotPositiveOrZero(0, TEST_PARAM));
        assertDoesNotThrow(() -> throwIfArgIsNotPositiveOrZero((short) 0, TEST_PARAM));
        assertDoesNotThrow(() -> throwIfArgIsNotPositiveOrZero((byte) 0, TEST_PARAM));
        assertDoesNotThrow(() -> throwIfArgIsNotPositiveOrZero(0L, TEST_PARAM));
        assertDoesNotThrow(() -> throwIfArgIsNotPositiveOrZero(0.0F, TEST_PARAM));
        assertDoesNotThrow(() -> throwIfArgIsNotPositiveOrZero(0.0, TEST_PARAM));
    }
}
