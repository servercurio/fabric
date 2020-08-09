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
import java.io.FileOutputStream;
import java.io.IOException;
import javax.imageio.ImageIO;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;


public abstract class AbstractScalrTest {
    protected static BufferedImage src;

    @BeforeAll
    public static void setup() throws IOException {
        src = load("time-square.png");
    }

    @AfterAll
    public static void tearDown() {
        src.flush();
    }

    protected static void assertEquals(BufferedImage orig, BufferedImage tmp)
            throws AssertionError {
        // Ensure neither image is null.
        Assertions.assertNotNull(orig);
        Assertions.assertNotNull(tmp);

        // Ensure dimensions are equal.
        Assertions.assertEquals(orig.getWidth(), tmp.getWidth());
        Assertions.assertEquals(orig.getHeight(), tmp.getHeight());

        int w = orig.getWidth();
        int h = orig.getHeight();

        // Ensure every RGB pixel value is the same.
        for (int i = 0; i < w; i++) {
            for (int j = 0; j < h; j++) {
                Assertions.assertEquals(orig.getRGB(i, j), tmp.getRGB(i, j));
            }
        }
    }

    protected static BufferedImage load(String name) {
        BufferedImage i = null;

        try {
            i = ImageIO.read(AbstractScalrTest.class.getResource(name));
        } catch (Exception e) {
            e.printStackTrace();
        }

        return i;
    }

    protected static void save(BufferedImage image, String name) {
        try {
            ImageIO.write(image, "PNG", new FileOutputStream(name));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}