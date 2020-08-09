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

import java.util.function.BooleanSupplier;

/**
 * Provides standardized validator logic to test for the conditions specified by the {@code javax.validation}
 * annotations.
 */
public final class Validators {

    /**
     * Private default constructor to prevent instantiation.
     */
    private Validators() {
    }

    /**
     * Throws an {@link IllegalArgumentException} if the supplied value is {@code null} or does not have a String length
     * that matches the specified {@code length} parameter.
     *
     * @param value
     *         the value to be tested, may be null
     * @param length
     *         the required length, positive or zero integer
     * @param name
     *         the name of the field or method parameter, not null
     * @throws IllegalArgumentException
     *         if the {@code value} parameter is null or does not have an array length as specified by the {@code
     *         length} parameter
     */
    public static void throwIfArgIsNotExactLength(final String value, final int length, final String name) {
        throwIfArgIsNull(value, name);

        if (value.length() != length) {
            throw new IllegalArgumentException(constrainParameter(name, mustLengthConstraint(length)));
        }
    }

    /**
     * Throws an {@link IllegalArgumentException} if the supplied value is {@code null} or does not have an array length
     * that matches the specified {@code length} parameter.
     *
     * @param value
     *         the value to be tested, may be null
     * @param length
     *         the required length, positive or zero integer
     * @param name
     *         the name of the field or method parameter, not null
     * @param <T>
     *         the type of the array elements
     * @throws IllegalArgumentException
     *         if the {@code value} parameter is null or does not have an array length as specified by the {@code
     *         length} parameter
     */
    public static <T> void throwIfArgIsNotExactLength(final T[] value, final int length, final String name) {
        throwIfArgIsNull(value, name);

        if (value.length != length) {
            throw new IllegalArgumentException(constrainParameter(name, mustLengthConstraint(length)));
        }
    }

    /**
     * Throws an {@link IllegalArgumentException} if the supplied value is {@code null} or does not have an array length
     * that matches the specified {@code length} parameter.
     *
     * @param value
     *         the value to be tested, may be null
     * @param length
     *         the required length, positive or zero integer
     * @param name
     *         the name of the field or method parameter, not null
     * @throws IllegalArgumentException
     *         if the {@code value} parameter is null or does not have an array length as specified by the {@code
     *         length} parameter
     */
    public static void throwIfArgIsNotExactLength(final byte[] value, final int length, final String name) {
        throwIfArgIsNull(value, name);

        if (value.length != length) {
            throw new IllegalArgumentException(constrainParameter(name, mustLengthConstraint(length)));
        }
    }

    /**
     * Throws an {@link IllegalArgumentException} if the supplied value is {@code null} or does not have an array length
     * that matches the specified {@code length} parameter.
     *
     * @param value
     *         the value to be tested, may be null
     * @param length
     *         the required length, positive or zero integer
     * @param name
     *         the name of the field or method parameter, not null
     * @param predicate
     *         the conditional test that must pass before the array length will be validated, not null
     * @throws IllegalArgumentException
     *         if the {@code value} parameter is null or does not have an array length as specified by the {@code
     *         length} parameter
     */
    public static void throwIfArgIsNotExactLength(final byte[] value, final int length, final String name,
                                                  final BooleanSupplier predicate) {
        throwIfArgIsNull(value, name);

        if (predicate.getAsBoolean() && value.length != length) {
            throw new IllegalArgumentException(constrainParameter(name, mustLengthConstraint(length)));
        }
    }

    /**
     * Throws an {@link IllegalArgumentException} if the supplied value is not a positive integer.
     *
     * @param value
     *         the value to be tested for empty, may be null
     * @param name
     *         the name of the field or method parameter, not null
     * @throws IllegalArgumentException
     *         if the {@code value} parameter is not a positive integer
     */
    public static void throwIfArgIsNotPositive(final int value, final String name) {
        if (value <= 0) {
            throw new IllegalArgumentException(constrainParameter(name, positiveIntegerConstraint()));
        }
    }

    /**
     * Throws an {@link IllegalArgumentException} if the supplied value is not a positive integer.
     *
     * @param value
     *         the value to be tested for empty, may be null
     * @param name
     *         the name of the field or method parameter, not null
     * @throws IllegalArgumentException
     *         if the {@code value} parameter is not a positive integer
     */
    public static void throwIfArgIsNotPositive(final long value, final String name) {
        if (value <= 0) {
            throw new IllegalArgumentException(constrainParameter(name, positiveIntegerConstraint()));
        }
    }

    /**
     * Throws an {@link IllegalArgumentException} if the supplied value is not a positive integer.
     *
     * @param value
     *         the value to be tested for empty, may be null
     * @param name
     *         the name of the field or method parameter, not null
     * @throws IllegalArgumentException
     *         if the {@code value} parameter is not a positive integer
     */
    public static void throwIfArgIsNotPositive(final short value, final String name) {
        if (value <= 0) {
            throw new IllegalArgumentException(constrainParameter(name, positiveIntegerConstraint()));
        }
    }

    /**
     * Throws an {@link IllegalArgumentException} if the supplied value is not a positive integer.
     *
     * @param value
     *         the value to be tested for empty, may be null
     * @param name
     *         the name of the field or method parameter, not null
     * @throws IllegalArgumentException
     *         if the {@code value} parameter is not a positive integer
     */
    public static void throwIfArgIsNotPositive(final byte value, final String name) {
        if (value <= 0) {
            throw new IllegalArgumentException(constrainParameter(name, positiveIntegerConstraint()));
        }
    }

    /**
     * Throws an {@link IllegalArgumentException} if the supplied value is not a positive integer.
     *
     * @param value
     *         the value to be tested for empty, may be null
     * @param name
     *         the name of the field or method parameter, not null
     * @throws IllegalArgumentException
     *         if the {@code value} parameter is not a positive integer
     */
    public static void throwIfArgIsNotPositive(final float value, final String name) {
        if (value <= 0) {
            throw new IllegalArgumentException(constrainParameter(name, positiveIntegerConstraint()));
        }
    }

    /**
     * Throws an {@link IllegalArgumentException} if the supplied value is not a positive integer.
     *
     * @param value
     *         the value to be tested for empty, may be null
     * @param name
     *         the name of the field or method parameter, not null
     * @throws IllegalArgumentException
     *         if the {@code value} parameter is not a positive integer
     */
    public static void throwIfArgIsNotPositive(final double value, final String name) {
        if (value <= 0) {
            throw new IllegalArgumentException(constrainParameter(name, positiveIntegerConstraint()));
        }
    }

    /**
     * Throws an {@link IllegalArgumentException} if the supplied value is not zero or a positive integer.
     *
     * @param value
     *         the value to be tested for empty, may be null
     * @param name
     *         the name of the field or method parameter, not null
     * @throws IllegalArgumentException
     *         if the {@code value} parameter is not a positive integer
     */
    public static void throwIfArgIsNotPositiveOrZero(final int value, final String name) {
        if (value < 0) {
            throw new IllegalArgumentException(constrainParameter(name, positiveOrZeroIntegerConstraint()));
        }
    }

    /**
     * Throws an {@link IllegalArgumentException} if the supplied value is not zero or a positive integer.
     *
     * @param value
     *         the value to be tested for empty, may be null
     * @param name
     *         the name of the field or method parameter, not null
     * @throws IllegalArgumentException
     *         if the {@code value} parameter is not a positive integer
     */
    public static void throwIfArgIsNotPositiveOrZero(final long value, final String name) {
        if (value < 0) {
            throw new IllegalArgumentException(constrainParameter(name, positiveOrZeroIntegerConstraint()));
        }
    }

    /**
     * Throws an {@link IllegalArgumentException} if the supplied value is not zero or a positive integer.
     *
     * @param value
     *         the value to be tested for empty, may be null
     * @param name
     *         the name of the field or method parameter, not null
     * @throws IllegalArgumentException
     *         if the {@code value} parameter is not a positive integer
     */
    public static void throwIfArgIsNotPositiveOrZero(final byte value, final String name) {
        if (value < 0) {
            throw new IllegalArgumentException(constrainParameter(name, positiveOrZeroIntegerConstraint()));
        }
    }

    /**
     * Throws an {@link IllegalArgumentException} if the supplied value is not zero or a positive integer.
     *
     * @param value
     *         the value to be tested for empty, may be null
     * @param name
     *         the name of the field or method parameter, not null
     * @throws IllegalArgumentException
     *         if the {@code value} parameter is not a positive integer
     */
    public static void throwIfArgIsNotPositiveOrZero(final short value, final String name) {
        if (value < 0) {
            throw new IllegalArgumentException(constrainParameter(name, positiveOrZeroIntegerConstraint()));
        }
    }

    /**
     * Throws an {@link IllegalArgumentException} if the supplied value is not zero or a positive integer.
     *
     * @param value
     *         the value to be tested for empty, may be null
     * @param name
     *         the name of the field or method parameter, not null
     * @throws IllegalArgumentException
     *         if the {@code value} parameter is not a positive integer
     */
    public static void throwIfArgIsNotPositiveOrZero(final float value, final String name) {
        if (value < 0) {
            throw new IllegalArgumentException(constrainParameter(name, positiveOrZeroIntegerConstraint()));
        }
    }

    /**
     * Throws an {@link IllegalArgumentException} if the supplied value is not zero or a positive integer.
     *
     * @param value
     *         the value to be tested for empty, may be null
     * @param name
     *         the name of the field or method parameter, not null
     * @throws IllegalArgumentException
     *         if the {@code value} parameter is not a positive integer
     */
    public static void throwIfArgIsNotPositiveOrZero(final double value, final String name) {
        if (value < 0) {
            throw new IllegalArgumentException(constrainParameter(name, positiveOrZeroIntegerConstraint()));
        }
    }

    /**
     * Throws an {@link IllegalArgumentException} if the supplied value is {@code null}.
     *
     * @param value
     *         the value to be tested for empty, may be null
     * @param name
     *         the name of the field or method parameter, not null
     * @throws IllegalArgumentException
     *         if the {@code value} parameter is {@code null}
     */
    public static void throwIfArgIsNull(final Object value, final String name) {
        if (value == null) {
            throw new IllegalArgumentException(constrainParameter(name, mustNotConstraint(null)));
        }
    }

    /**
     * Throws an {@link IllegalArgumentException} if the supplied value is {@code null}, an empty {@link String}, or a
     * zero-length array.
     *
     * @param value
     *         the value to be tested for empty, may be null
     * @param name
     *         the name of the field or method parameter, not null
     * @throws IllegalArgumentException
     *         if the {@code value} parameter is {@code null}, an empty String, or a zero-length array
     */
    public static void throwIfArgumentIsEmpty(final Object value, final String name) {
        throwIfArgIsNull(value, name);

        if (value instanceof String) {
            if (((String) value).isEmpty()) {
                throw new IllegalArgumentException(constrainParameter(name, mustNotConstraint("an empty string")));
            }
        } else if (value instanceof Object[]) {
            final Object[] arrayValue = (Object[]) value;

            if (arrayValue.length == 0) {
                throw new IllegalArgumentException(constrainParameter(name, mustNotConstraint("a zero-length array")));
            }
        }
    }

    /**
     * Throws an {@link IllegalArgumentException} if the supplied value is {@code null}, an empty {@link String}, or a
     * zero-length array.
     *
     * @param value
     *         the value to be tested for empty, may be null
     * @param name
     *         the name of the field or method parameter, not null
     * @throws IllegalArgumentException
     *         if the {@code value} parameter is {@code null}, an empty String, or a zero-length array
     */
    public static void throwIfArgumentIsEmpty(final byte[] value, final String name) {
        throwIfArgIsNull(value, name);

        if (value.length == 0) {
            throw new IllegalArgumentException(constrainParameter(name, mustNotConstraint("a zero-length array")));
        }
    }

    /**
     * Throws an {@link IllegalArgumentException} if the supplied value is {@code null}, an empty {@link String}, or a
     * zero-length array.
     *
     * @param value
     *         the value to be tested for empty, may be null
     * @param name
     *         the name of the field or method parameter, not null
     * @param predicate
     *         the conditional test that must pass before the emptiness will be validated, not null
     * @throws IllegalArgumentException
     *         if the {@code value} parameter is {@code null}, an empty String, or a zero-length array
     */
    public static void throwIfArgumentIsEmpty(final byte[] value, final String name, final BooleanSupplier predicate) {
        throwIfArgIsNull(value, name);

        if (predicate.getAsBoolean()) {
            throwIfArgumentIsEmpty(value, name);
        }
    }

    private static String constrainParameter(final String parameterName, final String constraint) {
        return String.format("The %s parameter %s", parameterName, constraint);
    }

    private static String mustConstraint(final Object value) {
        return String.format("must be %s", value);
    }

    private static String mustLengthConstraint(final int length) {
        return String.format("must have a length of %d", length);
    }

    private static String mustNotConstraint(final Object value) {
        return String.format("must not be %s", value);
    }

    private static String positiveIntegerConstraint() {
        return mustConstraint("a positive integer");
    }

    private static String positiveOrZeroIntegerConstraint() {
        return mustConstraint("zero or a positive integer");
    }

}
