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
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;


/**
 * The purpose of this test is to execute simultaneous scale operations on a very small picture as quickly as possible
 * to try and cause a dead-lock.
 *
 * @author Riyad Kalla (software@thebuzzmedia.com)
 */
@DisplayName("AsyncScalr: Multithreaded")
public class AsyncScalrMultiThreadTest extends AbstractScalrTest {
    private static int ITERS = 1000;
    private static final BufferedImage ORIG;

    static {
        System.setProperty(AsyncScalr.THREAD_COUNT_PROPERTY_NAME, "1");
        ORIG = load("mr-t.jpg");
    }

    @Test
    @DisplayName("AsyncScalr :: Multithreaded -> 1000 Iterations")
    public void test() throws InterruptedException {
        List<Thread> threadList = new ArrayList<Thread>(ITERS);

        for (int i = 0; i < ITERS; i++) {
            if (i % 100 == 0) {
                System.out.println("Scale Iteration " + i);
            }

            try {
                Thread t = new ScaleThread();
                t.start();
                threadList.add(t);
            } catch (OutOfMemoryError error) {
                System.out.println("Cannot create any more threads, last created was " + i);
                ITERS = i;
                break;
            }
        }

        // Now wait for all the threads to finish
        for (int i = 0; i < ITERS; i++) {
            if (i % 100 == 0) {
                System.out.println("Thread Finished " + i);
            }

            threadList.get(i).join();
        }

        // Make sure we finish with no exceptions.
        Assertions.assertTrue(true);
    }

    public class ScaleThread extends Thread {
        @Override
        public void run() {
            try {
                AsyncScalr.resize(ORIG, 125).get();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}