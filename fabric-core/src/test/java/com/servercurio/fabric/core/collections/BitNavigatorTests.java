/*
 * Copyright 2019 Server Curio
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

package com.servercurio.fabric.core.collections;

import org.junit.jupiter.api.*;

import static com.servercurio.fabric.core.collections.BitNavigator.msb;
import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("Collections: BitNavigator")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class BitNavigatorTests {

    @BeforeAll
    public static void startup() {

    }

    @AfterAll
    public static void shutdown() {

    }

    @Test
    @Order(100)
    @DisplayName("Binary :: Integer -> Most Significant Bit")
    public void testBinaryIntegerMsb() {
        assertEquals(256, msb(278));
        assertEquals(1024, msb(2040));
        assertEquals(0, msb(0));
        assertEquals(1, msb(1));
        assertEquals(0x08000000, msb(0x0FFFFFFF));
    }

    @Test
    @Order(200)
    @DisplayName("Binary :: Long -> Most Significant Bit")
    public void testBinaryLongMsb() {
        assertEquals(256L, msb(278L));
        assertEquals(1024L, msb(2040L));
        assertEquals(0L, msb(0L));
        assertEquals(1L, msb(1L));
        assertEquals(0x0800000000000000L, msb(0x0FFFFFFFFFFFFFFFL));
    }

    @Test
    @Order(300)
    @DisplayName("Navigate :: Small -> Insertion Point")
    public void testNavigateSmallInsertionPoint() {
        final BitNavigator navigator = new BitNavigator(5);

        assertEquals(5, navigator.getTreeSize());
        assertEquals(0, navigator.getTargetNode());

        navigator.insertion();
        assertEquals(3, navigator.getTargetNode());

        assertEquals(NavigationStep.RIGHT, navigator.nextStep());
        assertEquals(NavigationStep.COMPLETE, navigator.nextStep());
    }

    @Test
    @Order(301)
    @DisplayName("Navigate :: Small -> Last Leaf")
    public void testNavigateSmallLastLeaf() {
        final BitNavigator navigator = new BitNavigator(5, 5);

        assertEquals(5, navigator.getTreeSize());
        assertEquals(5, navigator.getTargetNode());

        assertEquals(NavigationStep.LEFT, navigator.nextStep());
        assertEquals(NavigationStep.RIGHT, navigator.nextStep());
        assertEquals(NavigationStep.COMPLETE, navigator.nextStep());
    }

    @Test
    @Order(302)
    @DisplayName("Navigate :: Small -> Right Most Leaf")
    public void testNavigateSmallRightMostLeaf() {
        final BitNavigator navigator = new BitNavigator(5);

        assertEquals(5, navigator.getTreeSize());
        assertEquals(0, navigator.getTargetNode());

        navigator.rightMostLeaf();
        assertEquals(3, navigator.getTargetNode());

        assertEquals(NavigationStep.RIGHT, navigator.nextStep());
        assertEquals(NavigationStep.COMPLETE, navigator.nextStep());
    }


    @Test
    @Order(400)
    @DisplayName("Navigate :: Medium -> Insertion Point")
    public void testNavigateMediumInsertionPoint() {
        final BitNavigator navigator = new BitNavigator(7);

        assertEquals(7, navigator.getTreeSize());
        assertEquals(0, navigator.getTargetNode());

        navigator.insertion();
        assertEquals(4, navigator.getTargetNode());

        assertEquals(NavigationStep.LEFT, navigator.nextStep());
        assertEquals(NavigationStep.LEFT, navigator.nextStep());
        assertEquals(NavigationStep.COMPLETE, navigator.nextStep());
    }

    @Test
    @Order(401)
    @DisplayName("Navigate :: Medium -> Last Leaf")
    public void testNavigateMediumLastLeaf() {
        final BitNavigator navigator = new BitNavigator(7, 7);

        assertEquals(7, navigator.getTreeSize());
        assertEquals(7, navigator.getTargetNode());

        assertEquals(NavigationStep.RIGHT, navigator.nextStep());
        assertEquals(NavigationStep.RIGHT, navigator.nextStep());
        assertEquals(NavigationStep.COMPLETE, navigator.nextStep());
    }

    @Test
    @Order(402)
    @DisplayName("Navigate :: Medium -> Right Most Leaf")
    public void testNavigateMediumRightMostLeaf() {
        final BitNavigator navigator = new BitNavigator(7);

        assertEquals(7, navigator.getTreeSize());
        assertEquals(0, navigator.getTargetNode());

        navigator.rightMostLeaf();
        assertEquals(7, navigator.getTargetNode());

        assertEquals(NavigationStep.RIGHT, navigator.nextStep());
        assertEquals(NavigationStep.RIGHT, navigator.nextStep());
        assertEquals(NavigationStep.COMPLETE, navigator.nextStep());
    }

    @Test
    @Order(500)
    @DisplayName("Navigate :: Medium Large -> Insertion Point")
    public void testNavigateMediumLargeInsertionPoint() {
        final BitNavigator navigator = new BitNavigator(9);

        assertEquals(9, navigator.getTreeSize());
        assertEquals(0, navigator.getTargetNode());

        navigator.insertion();
        assertEquals(5, navigator.getTargetNode());

        assertEquals(NavigationStep.LEFT, navigator.nextStep());
        assertEquals(NavigationStep.RIGHT, navigator.nextStep());
        assertEquals(NavigationStep.COMPLETE, navigator.nextStep());
    }

    @Test
    @Order(501)
    @DisplayName("Navigate :: Medium Large -> Last Leaf")
    public void testNavigateMediumLargeLastLeaf() {
        final BitNavigator navigator = new BitNavigator(9, 9);

        assertEquals(9, navigator.getTreeSize());
        assertEquals(9, navigator.getTargetNode());

        assertEquals(NavigationStep.LEFT, navigator.nextStep());
        assertEquals(NavigationStep.LEFT, navigator.nextStep());
        assertEquals(NavigationStep.RIGHT, navigator.nextStep());
        assertEquals(NavigationStep.COMPLETE, navigator.nextStep());
    }

    @Test
    @Order(502)
    @DisplayName("Navigate :: Medium Large -> Right Most Leaf")
    public void testNavigateMediumLargeRightMostLeaf() {
        final BitNavigator navigator = new BitNavigator(9);

        assertEquals(9, navigator.getTreeSize());
        assertEquals(0, navigator.getTargetNode());

        navigator.rightMostLeaf();
        assertEquals(7, navigator.getTargetNode());

        assertEquals(NavigationStep.RIGHT, navigator.nextStep());
        assertEquals(NavigationStep.RIGHT, navigator.nextStep());
        assertEquals(NavigationStep.COMPLETE, navigator.nextStep());
    }

    @Test
    @Order(600)
    @DisplayName("Navigate :: Large -> Insertion Point")
    public void testNavigateLargeInsertionPoint() {
        final BitNavigator navigator = new BitNavigator(11);

        assertEquals(11, navigator.getTreeSize());
        assertEquals(0, navigator.getTargetNode());

        navigator.insertion();
        assertEquals(6, navigator.getTargetNode());

        assertEquals(NavigationStep.RIGHT, navigator.nextStep());
        assertEquals(NavigationStep.LEFT, navigator.nextStep());
        assertEquals(NavigationStep.COMPLETE, navigator.nextStep());
    }

    @Test
    @Order(601)
    @DisplayName("Navigate :: Large -> Last Leaf")
    public void testNavigateLargeLastLeaf() {
        final BitNavigator navigator = new BitNavigator(11, 11);

        assertEquals(11, navigator.getTreeSize());
        assertEquals(11, navigator.getTargetNode());

        assertEquals(NavigationStep.LEFT, navigator.nextStep());
        assertEquals(NavigationStep.RIGHT, navigator.nextStep());
        assertEquals(NavigationStep.RIGHT, navigator.nextStep());
        assertEquals(NavigationStep.COMPLETE, navigator.nextStep());
    }

    @Test
    @Order(602)
    @DisplayName("Navigate :: Large -> Right Most Leaf")
    public void testNavigateLargeRightMostLeaf() {
        final BitNavigator navigator = new BitNavigator(11);

        assertEquals(11, navigator.getTreeSize());
        assertEquals(0, navigator.getTargetNode());

        navigator.rightMostLeaf();
        assertEquals(7, navigator.getTargetNode());

        assertEquals(NavigationStep.RIGHT, navigator.nextStep());
        assertEquals(NavigationStep.RIGHT, navigator.nextStep());
        assertEquals(NavigationStep.COMPLETE, navigator.nextStep());
    }

    @Test
    @Order(700)
    @DisplayName("Navigate :: Empty -> Insertion Point")
    public void testNavigateEmptyInsertionPoint() {
        final BitNavigator navigator = new BitNavigator(0);

        assertEquals(0, navigator.getTreeSize());
        assertEquals(0, navigator.getTargetNode());

        navigator.insertion();
        assertEquals(1, navigator.getTargetNode());

        assertEquals(NavigationStep.COMPLETE, navigator.nextStep());
    }

    @Test
    @Order(701)
    @DisplayName("Navigate :: Empty -> Last Leaf")
    public void testNavigateEmptyLastLeaf() {
        final BitNavigator navigator = new BitNavigator(0, 0);

        assertEquals(0, navigator.getTreeSize());
        assertEquals(0, navigator.getTargetNode());

        assertEquals(NavigationStep.COMPLETE, navigator.nextStep());
    }

    @Test
    @Order(702)
    @DisplayName("Navigate :: Empty -> Right Most Leaf")
    public void testNavigateEmptyRightMostLeaf() {
        final BitNavigator navigator = new BitNavigator(0);

        assertEquals(0, navigator.getTreeSize());
        assertEquals(0, navigator.getTargetNode());

        navigator.rightMostLeaf();
        assertEquals(0, navigator.getTargetNode());

        assertEquals(NavigationStep.COMPLETE, navigator.nextStep());
    }
}