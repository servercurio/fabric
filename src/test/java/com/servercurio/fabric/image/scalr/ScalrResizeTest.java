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

import java.awt.image.BufferedImage;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Scalr: Resize")
public class ScalrResizeTest extends AbstractScalrTest {
    @Test
    @DisplayName("Resize :: Fit Exact vs Fit Both")
    public void testResizeAutoVsFitBoth() {
        // FitBoth will not allow the minor axis to grow beyond the specified box. The four commented
        // tests show how this interacts

        // For landscape images, AUTO will let targetWidth decide scaling, even if targetHeight is violated
        BufferedImage landscape = new BufferedImage(500, 250, BufferedImage.TYPE_INT_RGB);
        testResizeAutoVsBoth(landscape, 500, 250, 500, 250, 500, 250);
        testResizeAutoVsBoth(landscape, 500, 500, 500, 250, 500, 250);

        testResizeAutoVsBoth(landscape, 800, 300, 800, 400, 600, 300);  // FitBoth restricts y to 300, and adjusts x
        testResizeAutoVsBoth(landscape, 800, 400, 800, 400, 800, 400);
        testResizeAutoVsBoth(landscape, 800, 500, 800, 400, 800, 400);

        testResizeAutoVsBoth(landscape, 250, 150, 250, 125, 250, 125);
        testResizeAutoVsBoth(landscape, 250, 125, 250, 125, 250, 125);
        testResizeAutoVsBoth(landscape, 250, 100, 250, 125, 200, 100);  // FitBoth imposes smaller y, and adjusts x

        // For portrait images, AUTO will let targetHeight decide scaling, even if targetWidth is violated
        BufferedImage portrait = new BufferedImage(250, 500, BufferedImage.TYPE_INT_RGB);
        testResizeAutoVsBoth(portrait, 250, 500, 250, 500, 250, 500);
        testResizeAutoVsBoth(portrait, 500, 500, 250, 500, 250, 500);

        testResizeAutoVsBoth(portrait, 300, 800, 400, 800, 300, 600);   // FitBoth restricts x to 800, and adjusts y
        testResizeAutoVsBoth(portrait, 400, 800, 400, 800, 400, 800);
        testResizeAutoVsBoth(portrait, 500, 800, 400, 800, 400, 800);

        testResizeAutoVsBoth(portrait, 150, 250, 125, 250, 125, 250);
        testResizeAutoVsBoth(portrait, 125, 250, 125, 250, 125, 250);
        testResizeAutoVsBoth(portrait, 100, 250, 125, 250, 100, 200);   // FitBoth imposes smaller xj, and adjusts y

        // Squares are treated as a landscape
        BufferedImage square = new BufferedImage(500, 500, BufferedImage.TYPE_INT_RGB);
        testResizeAutoVsBoth(square, 500, 500, 500, 500, 500, 500);
        testResizeAutoVsBoth(square, 800, 800, 800, 800, 800, 800);
        testResizeAutoVsBoth(square, 400, 400, 400, 400, 400, 400);
        testResizeAutoVsBoth(square, 800, 600, 800, 800, 600, 600);     // FixBoth restricts both dimensions

    }

    @Test
    @DisplayName("Resize :: Exceptions")
    public void testResizeEX() {
        try {
            Scalr.resize(src, -1);
            Assertions.assertTrue(false);
        } catch (IllegalArgumentException e) {
            Assertions.assertTrue(true);
        }

        try {
            Scalr.resize(src, 240, -1);
            Assertions.assertTrue(false);
        } catch (IllegalArgumentException e) {
            Assertions.assertTrue(true);
        }

        try {
            Scalr.resize(src, (Scalr.Method) null, 240);
            Assertions.assertTrue(false);
        } catch (IllegalArgumentException e) {
            Assertions.assertTrue(true);
        }

        try {
            Scalr.resize(src, (Scalr.Mode) null, 240);
            Assertions.assertTrue(false);
        } catch (IllegalArgumentException e) {
            Assertions.assertTrue(true);
        }

        try {
            Scalr.resize(src, (Scalr.Method) null, 240, 240);
            Assertions.assertTrue(false);
        } catch (IllegalArgumentException e) {
            Assertions.assertTrue(true);
        }

        try {
            Scalr.resize(src, (Scalr.Mode) null, 240, 240);
            Assertions.assertTrue(false);
        } catch (IllegalArgumentException e) {
            Assertions.assertTrue(true);
        }

        try {
            Scalr.resize(src, null, null, 240);
            Assertions.assertTrue(false);
        } catch (IllegalArgumentException e) {
            Assertions.assertTrue(true);
        }

        try {
            Scalr.resize(src, null, null, 240, 240);
            Assertions.assertTrue(false);
        } catch (IllegalArgumentException e) {
            Assertions.assertTrue(true);
        }
    }

    @Test
    @DisplayName("Resize :: Fit Exact Square Dimensions")
    public void testResizeFitExact() {
        BufferedImage i = new BufferedImage(500, 500, BufferedImage.TYPE_INT_RGB);
        BufferedImage i2 = Scalr.resize(i, Scalr.Mode.FIT_EXACT, 500, 250);

        Assertions.assertEquals(500, i2.getWidth());
        Assertions.assertEquals(250, i2.getHeight());
    }

    @Test
    @DisplayName("Resize :: Square")
    public void testResizeSize() {
        assertEquals(load("time-square-resize-320.png"), Scalr.resize(src, 320));
    }

    @Test
    @DisplayName("Resize :: Fit Exact Square")
    public void testResizeSizeExact() {
        assertEquals(load("time-square-resize-320-fit-exact.png"),
                     Scalr.resize(src, Scalr.Mode.FIT_EXACT, 320));
    }

    @Test
    @DisplayName("Resize :: Speed Square")
    public void testResizeSizeSpeed() {
        assertEquals(load("time-square-resize-320-speed.png"),
                     Scalr.resize(src, Scalr.Method.SPEED, 320));
    }

    @Test
    @DisplayName("Resize :: Speed Exact Square")
    public void testResizeSizeSpeedExact() {
        assertEquals(load("time-square-resize-320-speed-fit-exact.png"),
                     Scalr.resize(src, Scalr.Method.SPEED, Scalr.Mode.FIT_EXACT, 320));
    }

    @Test
    @DisplayName("Resize :: Ultra Square")
    public void testResizeUltraQuality() {
        BufferedImage i = new BufferedImage(32, 32, BufferedImage.TYPE_INT_RGB);
        Scalr.resize(i, Scalr.Method.ULTRA_QUALITY, 1);

        // This test is really about having scaling to tiny sizes not looping
        // forever because of the fractional step-down calculation bottoming
        // out.
        Assertions.assertTrue(true);
    }

    @Test
    @DisplayName("Resize :: Width & Height")
    public void testResizeWH() {
        assertEquals(load("time-square-resize-640x480.png"),
                     Scalr.resize(src, 640, 480));
    }

    @Test
    @DisplayName("Resize :: Fit Exact Width & Height")
    public void testResizeWHExact() {
        assertEquals(load("time-square-resize-640x640-fit-exact.png"),
                     Scalr.resize(src, Scalr.Mode.FIT_EXACT, 640, 640));
    }

    @Test
    @DisplayName("Resize :: Speed Width & Height")
    public void testResizeWHSpeed() {
        assertEquals(load("time-square-resize-640x480-speed.png"),
                     Scalr.resize(src, Scalr.Method.SPEED, 640, 480));
    }

    @Test
    @DisplayName("Resize :: Speed Exact Width & Height")
    public void testResizeWHSpeedExact() {
        assertEquals(load("time-square-resize-640x640-speed-fit-exact.png"),
                     Scalr.resize(src, Scalr.Method.SPEED, Scalr.Mode.FIT_EXACT, 640, 640));
    }

    @Test
    @DisplayName("Resize :: Speed Exact Width & Height Grayscale Op")
    public void testResizeWHSpeedExactOps() {
        assertEquals(
                load("time-square-resize-640x640-speed-fit-exact-ops.png"),
                Scalr.resize(src, Scalr.Method.SPEED, Scalr.Mode.FIT_EXACT, 640, 640,
                             Scalr.OP_GRAYSCALE));
    }

    // resize to (w,h) using AUTO and FIT_BOTH modes, then compare auto (w,h) and fitBoth (w,h)
    private void testResizeAutoVsBoth(BufferedImage i, int targetWidth, int targetHeight, int autoWidth, int autoHeight,
                                      int fitBothWidth, int fitBothHeight) {
        BufferedImage auto = Scalr.resize(i, Scalr.Mode.AUTOMATIC, targetWidth, targetHeight);
        BufferedImage fitBoth = Scalr.resize(i, Scalr.Mode.BEST_FIT_BOTH, targetWidth, targetHeight);

        Assertions.assertEquals(autoWidth, auto.getWidth());
        Assertions.assertEquals(autoHeight, auto.getHeight());

        Assertions.assertEquals(fitBothWidth, fitBoth.getWidth());
        Assertions.assertEquals(fitBothHeight, fitBoth.getHeight());
    }
}