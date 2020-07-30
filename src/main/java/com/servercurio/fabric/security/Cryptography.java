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

package com.servercurio.fabric.security;

import com.servercurio.fabric.security.impl.DefaultCryptographyImpl;
import com.servercurio.fabric.security.spi.DigestProvider;
import com.servercurio.fabric.security.spi.EncryptionProvider;
import com.servercurio.fabric.security.spi.MacProvider;
import com.servercurio.fabric.security.spi.SignatureProvider;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.validation.constraints.NotNull;

/**
 * Provides the unified Cryptography API for the {@code Fabric} library. The core API is broken down into multiple
 * provider interfaces. The providers encapsulate the discrete cryptographic functions. All implementors of the {@link
 * Cryptography} interface must provide implementations for the providers listed below:
 *
 * <p>
 * <ul>
 *     <li>{@link DigestProvider}</li>
 *     <li>{@link MacProvider}</li>
 *     <li>{@link EncryptionProvider}</li>
 *     <li>{@link SignatureProvider}</li>
 * </ul>
 *
 * @author Nathan Klick
 * @see DigestProvider
 * @see MacProvider
 * @see EncryptionProvider
 * @see SignatureProvider
 * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html">Java
 *         Cryptography Architecture</a>
 */
public interface Cryptography extends AutoCloseable {

    /**
     * Factory method for new instances of the default cryptography implementation.
     *
     * @return a new {@link Cryptography} instance using the default implementation, not null
     */
    static Cryptography newDefaultInstance() {
        return DefaultCryptographyImpl.newInstance();
    }

    /**
     * Provides all the cryptographic hash functionality.
     *
     * @return the provider associated with this {@link Cryptography} instance, not null
     */
    DigestProvider digest();

    /**
     * Provides all the cryptographic encryption functionality.
     *
     * @return the provider associated with this {@link Cryptography} instance, not null
     */
    EncryptionProvider encryption();

    /**
     * Provides all the cryptographic message authentication functionality.
     *
     * @return the provider associated with this {@link Cryptography} instance, not null
     */
    MacProvider mac();

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
    Cipher primitive(@NotNull final CipherTransformation algorithm);

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
    Signature primitive(@NotNull final SignatureAlgorithm algorithm);

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
    MessageDigest primitive(@NotNull final HashAlgorithm algorithm);

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
    Mac primitive(@NotNull final MacAlgorithm algorithm);

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
        if (left == null) {
            throw new IllegalArgumentException("left");
        }

        if (right == null) {
            throw new IllegalArgumentException("right");
        }

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
        if (left == null) {
            throw new IllegalArgumentException("left");
        }

        if (right == null) {
            throw new IllegalArgumentException("right");
        }

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
        if (left == null) {
            throw new IllegalArgumentException("left");
        }

        if (right == null) {
            throw new IllegalArgumentException("right");
        }

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
        if (left == null) {
            throw new IllegalArgumentException("left");
        }

        if (right == null) {
            throw new IllegalArgumentException("right");
        }

        int diff = left.length ^ right.length;
        for (int i = 0; i < left.length && i < right.length; i++) {
            diff |= left[i] ^ right[i];
        }
        return diff == 0;
    }

    /**
     * Provides all the cryptographic digital signature functionality.
     *
     * @return the provider associated with this {@link Cryptography} instance, not null
     */
    SignatureProvider signature();

    /**
     * {@inheritDoc}
     */
    @Override
    void close();
}
