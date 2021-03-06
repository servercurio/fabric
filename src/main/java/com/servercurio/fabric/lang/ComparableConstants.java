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

/**
 * Constants for use with {@link Comparable#compareTo(Object)} implementations.
 *
 * @author Nathan Klick
 * @see Comparable#compareTo(Object)
 */
public final class ComparableConstants {

    /**
     * The {@link Comparable#compareTo(Object)} return value indicating that the {@code this} instance is less than the
     * {@code other} instance.
     */
    public static final int LESS_THAN = -1;

    /**
     * The {@link Comparable#compareTo(Object)} return value indicating that the {@code this} instance is equal to the
     * {@code other} instance.
     */
    public static final int EQUAL = 0;

    /**
     * The {@link Comparable#compareTo(Object)} return value indicating that the {@code this} instance is greater than
     * the {@code other} instance.
     */
    public static final int GREATER_THAN = 1;

    /**
     * Private default constructor to prevent instantiation.
     */
    private ComparableConstants() {

    }

}
