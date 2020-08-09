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


import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Scalr: Rotate")
public class ScalrRotateTest extends AbstractScalrTest {
    @Test
    @DisplayName("Rotate :: 180 Degrees")
    public void testRotate180() {
        assertEquals(load("time-square-rotate-180.png"),
                     Scalr.rotate(load("time-square.png"), Scalr.Rotation.CW_180));
    }

    @Test
    @DisplayName("Rotate :: 270 Degrees")
    public void testRotate270() {
        assertEquals(load("time-square-rotate-270.png"),
                     Scalr.rotate(load("time-square.png"), Scalr.Rotation.CW_270));
    }

    @Test
    @DisplayName("Rotate :: 90 Degrees")
    public void testRotate90() {
        assertEquals(load("time-square-rotate-90.png"),
                     Scalr.rotate(load("time-square.png"), Scalr.Rotation.CW_90));
    }

    @Test
    @DisplayName("Rotate :: Exceptions")
    public void testRotateEX() {
        try {
            Scalr.rotate(src, null);
            Assertions.assertTrue(false);
        } catch (IllegalArgumentException e) {
            Assertions.assertTrue(true);
        }
    }

    @Test
    @DisplayName("Rotate :: Flip Horizontal")
    public void testRotateFlipH() {
        assertEquals(load("time-square-rotate-horz.png"),
                     Scalr.rotate(load("time-square.png"), Scalr.Rotation.FLIP_HORIZONTAL));
    }

    @Test
    @DisplayName("Rotate :: Flip Horizontal Grayscale Op")
    public void testRotateFlipHOps() {
        assertEquals(load("time-square-rotate-horz-ops.png"),
                     Scalr.rotate(load("time-square.png"), Scalr.Rotation.FLIP_HORIZONTAL,
                                  Scalr.OP_GRAYSCALE));
    }

    @Test
    @DisplayName("Rotate :: Flip Vertical")
    public void testRotateFlipV() {
        assertEquals(load("time-square-rotate-vert.png"),
                     Scalr.rotate(load("time-square.png"), Scalr.Rotation.FLIP_VERTICAL));
    }
}