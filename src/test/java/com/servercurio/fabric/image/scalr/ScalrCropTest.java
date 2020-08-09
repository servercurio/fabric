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

import static com.servercurio.fabric.image.scalr.Scalr.crop;

@DisplayName("Scalr: Crop")
public class ScalrCropTest extends AbstractScalrTest {

    @Test
    @DisplayName("Crop :: Exceptions")
    public void testCropEX() {
        try {
            crop(src, 3200, 2400);
            Assertions.assertTrue(false);
        } catch (Exception e) {
            Assertions.assertTrue(true);
        }

        try {
            crop(src, -8, -10, 100, 100);
            Assertions.assertTrue(false);
        } catch (Exception e) {
            Assertions.assertTrue(true);
        }

        try {
            crop(src, -100, -200, -4, -4);
            Assertions.assertTrue(false);
        } catch (Exception e) {
            Assertions.assertTrue(true);
        }
    }

    @Test
    @DisplayName("Crop :: Width & Height -> Whole Image")
    public void testCropWH() {
        assertEquals(load("time-square-crop-wh.png"), crop(src, 320, 240));
    }

    @Test
    @DisplayName("Crop :: Width & Height -> XY Coordinates")
    public void testCropXYWH() {
        assertEquals(load("time-square-crop-xywh.png"),
                     crop(src, 100, 100, 320, 240));
    }

    @Test
    @DisplayName("Crop :: Width & Height -> XY Coordinates Grayscale Op")
    public void testCropXYWHOps() {
        assertEquals(load("time-square-crop-xywh-ops.png"),
                     crop(src, 100, 100, 320, 240, Scalr.OP_GRAYSCALE));
    }
}