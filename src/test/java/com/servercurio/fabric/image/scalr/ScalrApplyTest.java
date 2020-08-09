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
package com.servercurio.fabric.image.scalr;


import java.awt.image.BufferedImageOp;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.servercurio.fabric.image.scalr.Scalr.OP_ANTIALIAS;
import static com.servercurio.fabric.image.scalr.Scalr.OP_BRIGHTER;
import static com.servercurio.fabric.image.scalr.Scalr.OP_DARKER;
import static com.servercurio.fabric.image.scalr.Scalr.OP_GRAYSCALE;
import static com.servercurio.fabric.image.scalr.Scalr.apply;

@DisplayName("Scalr: Apply")
public class ScalrApplyTest extends AbstractScalrTest {

    @Test
    @DisplayName("Apply :: One Operation")
    public void testApply1() {
        assertEquals(load("time-square-apply-1.png"), apply(src, OP_ANTIALIAS));
    }

    @Test
    @DisplayName("Apply :: Four Operations")
    public void testApply4() {
        assertEquals(load("time-square-apply-4.png"),
                     apply(src, Scalr.OP_ANTIALIAS, OP_BRIGHTER, OP_DARKER, OP_GRAYSCALE));
    }

    @Test
    @DisplayName("Apply :: Exceptions")
    public void testApplyEX() {
        try {
            apply(src, (BufferedImageOp[]) null);
            Assertions.assertTrue(false);
        } catch (Exception e) {
            Assertions.assertTrue(true);
        }
    }

    @Test
    @DisplayName("Apply :: Grayscale")
    public void testApplyGrayscale() {
        assertEquals(load("time-square-apply-grayscale.png"), apply(src, OP_GRAYSCALE));
    }

}