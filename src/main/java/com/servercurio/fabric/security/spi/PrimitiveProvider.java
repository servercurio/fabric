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

package com.servercurio.fabric.security.spi;

import com.servercurio.fabric.security.CipherTransformation;
import com.servercurio.fabric.security.HashAlgorithm;
import com.servercurio.fabric.security.MacAlgorithm;
import com.servercurio.fabric.security.SignatureAlgorithm;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.validation.constraints.NotNull;

import static com.servercurio.fabric.lang.Validators.throwIfArgIsNull;


/**
 * {@code Fabric Unified Cryptography API} provider definition that encapsulates the ability to request cryptographic
 * primitives from the underlying Java Cryptography Architecture providers.
 *
 * @author Nathan Klick
 */
public interface PrimitiveProvider {

    /**
     * Acquires a cryptographic primitive from the underlying Java Cryptography Architecture provider. Implementations
     * may return a new primitive on every request or may return a cached instance. If returning cached instances then
     * care must be taken to ensure thread safety and that cached instances are only used by a single caller at a time.
     *
     * @param algorithm
     *         the cryptographic algorithm, not null
     * @return the cryptographic primitive, not null
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html">Java
     *         Cryptography Architecture</a>
     */
    Cipher primitive(@NotNull CipherTransformation algorithm);

    /**
     * Acquires a cryptographic primitive from the underlying Java Cryptography Architecture provider. Implementations
     * may return a new primitive on every request or may return a cached instance. If returning cached instances then
     * care must be taken to ensure thread safety and that cached instances are only used by a single caller at a time.
     *
     * @param algorithm
     *         the cryptographic algorithm, not null
     * @return the cryptographic primitive, not null
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html">Java
     *         Cryptography Architecture</a>
     */
    Signature primitive(@NotNull SignatureAlgorithm algorithm);

    /**
     * Acquires a cryptographic primitive from the underlying Java Cryptography Architecture provider. Implementations
     * may return a new primitive on every request or may return a cached instance. If returning cached instances then
     * care must be taken to ensure thread safety and that cached instances are only used by a single caller at a time.
     *
     * @param algorithm
     *         the cryptographic algorithm, not null
     * @return the cryptographic primitive, not null
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html">Java
     *         Cryptography Architecture</a>
     */
    MessageDigest primitive(@NotNull HashAlgorithm algorithm);

    /**
     * Acquires a cryptographic primitive from the underlying Java Cryptography Architecture provider. Implementations
     * may return a new primitive on every request or may return a cached instance. If returning cached instances then
     * care must be taken to ensure thread safety and that cached instances are only used by a single caller at a time.
     *
     * @param algorithm
     *         the cryptographic algorithm, not null
     * @return the cryptographic primitive, not null
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html">Java
     *         Cryptography Architecture</a>
     */
    Mac primitive(@NotNull MacAlgorithm algorithm);

    /**
     * Acquires an instance of a cryptographically secure PRNG. It is strongly recommended that all implementations use
     * the DRBG secure random algorithm with reseeding enabled and no less than a 128-bit strength parameter.
     *
     * @return a cryptographically secure PRNG implementation, not null
     * @see java.security.DrbgParameters
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html">Java
     *         Cryptography Architecture</a>
     */
    SecureRandom random();

    /**
     * Secure equality comparison that uses a constant time comparison operation. This implementation uses XOR based
     * operations to provide the constant time comparisons. The use of constant time operations are critical to help
     * mitigate processor timing attacks.
     *
     * @param left
     *         the first array being compared, not null
     * @param right
     *         the second array being compared, not null
     * @return true if both arrays are the same length and contain the same elements in the same order; otherwise false
     *         if the arrays are not equal
     * @throws IllegalArgumentException
     *         if the {@code left} or {@code right} parameters are {@code null}
     */
    default boolean secureEquals(@NotNull final char[] left, @NotNull final char[] right) {
        throwIfArgIsNull(left, "left");
        throwIfArgIsNull(right, "right");

        int diff = left.length ^ right.length;
        for (int i = 0; i < left.length && i < right.length; i++) {
            diff |= left[i] ^ right[i];
        }
        return diff == 0;
    }

    /**
     * Secure equality comparison that uses a constant time comparison operation. This implementation uses XOR based
     * operations to provide the constant time comparisons. The use of constant time operations are critical to help
     * mitigate processor timing attacks.
     *
     * @param left
     *         the first array being compared, not null
     * @param right
     *         the second array being compared, not null
     * @return true if both arrays are the same length and contain the same elements in the same order; otherwise false
     *         if the arrays are not equal
     * @throws IllegalArgumentException
     *         if the {@code left} or {@code right} parameters are {@code null}
     */
    default boolean secureEquals(@NotNull final byte[] left, @NotNull final byte[] right) {
        throwIfArgIsNull(left, "left");
        throwIfArgIsNull(right, "right");

        int diff = left.length ^ right.length;
        for (int i = 0; i < left.length && i < right.length; i++) {
            diff |= left[i] ^ right[i];
        }
        return diff == 0;
    }

    /**
     * Secure equality comparison that uses a constant time comparison operation. This implementation uses XOR based
     * operations to provide the constant time comparisons. The use of constant time operations are critical to help
     * mitigate processor timing attacks.
     *
     * @param left
     *         the first array being compared, not null
     * @param right
     *         the second array being compared, not null
     * @return true if both arrays are the same length and contain the same elements in the same order; otherwise false
     *         if the arrays are not equal
     * @throws IllegalArgumentException
     *         if the {@code left} or {@code right} parameters are {@code null}
     */
    default boolean secureEquals(@NotNull final int[] left, @NotNull final int[] right) {
        throwIfArgIsNull(left, "left");
        throwIfArgIsNull(right, "right");

        int diff = left.length ^ right.length;
        for (int i = 0; i < left.length && i < right.length; i++) {
            diff |= left[i] ^ right[i];
        }
        return diff == 0;
    }

    /**
     * Secure equality comparison that uses a constant time comparison operation. This implementation uses XOR based
     * operations to provide the constant time comparisons. The use of constant time operations are critical to help
     * mitigate processor timing attacks.
     *
     * @param left
     *         the first array being compared, not null
     * @param right
     *         the second array being compared, not null
     * @return true if both arrays are the same length and contain the same elements in the same order; otherwise false
     *         if the arrays are not equal
     * @throws IllegalArgumentException
     *         if the {@code left} or {@code right} parameters are {@code null}
     */
    default boolean secureEquals(@NotNull final long[] left, @NotNull final long[] right) {
        throwIfArgIsNull(left, "left");
        throwIfArgIsNull(right, "right");

        int diff = left.length ^ right.length;
        for (int i = 0; i < left.length && i < right.length; i++) {
            diff |= left[i] ^ right[i];
        }
        return diff == 0;
    }
}
