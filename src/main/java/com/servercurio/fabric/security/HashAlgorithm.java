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

import com.servercurio.fabric.security.spi.CryptoPrimitiveSupplier;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.util.HashMap;
import java.util.Map;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Positive;

/**
 * An enumeration of the standard cryptographic hash algorithms along with their initialization parameters.
 */
public enum HashAlgorithm implements CryptoPrimitiveSupplier<MessageDigest> {
    /**
     * Represents no algorithm specified or an unknown algorithm was used.
     */
    NONE(0, "NONE", 0),

    /**
     * The SHA-1 algorithm as defined by NIST FIPS 180-4.
     *
     * @see <a href="https://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">
     *     https://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf</a>
     */
    SHA1(1, "SHA-1", 160),

    /**
     * The SHA-224 algorithm as defined by NIST FIPS 180-4.
     *
     * @see <a href="https://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">
     *     https://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf</a>
     */
    SHA_224(2, "SHA-224", 224),

    /**
     * The SHA-256 algorithm as defined by NIST FIPS 180-4.
     *
     * @see <a href="https://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">
     *     https://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf</a>
     */
    SHA_256(3, "SHA-256", 256),

    /**
     * The SHA-384 algorithm as defined by NIST FIPS 180-4.
     *
     * @see <a href="https://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">
     *     https://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf</a>
     */
    SHA_384(4, "SHA-384", 384),

    /**
     * The SHA-512 algorithm as defined by NIST FIPS 180-4.
     *
     * @see <a href="https://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">
     *     https://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf</a>
     */
    SHA_512(5, "SHA-512", 512),

    /**
     * The SHA3-224 algorithm as defined by NIST FIPS 202.
     *
     * @see <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">
     *         https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf</a>
     */
    SHA3_224(6, "SHA3-224", 224),

    /**
     * The SHA3-256 algorithm as defined by NIST FIPS 202.
     *
     * @see <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">
     *         https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf</a>
     */
    SHA3_256(7, "SHA3-256", 256),

    /**
     * The SHA3-384 algorithm as defined by NIST FIPS 202.
     *
     * @see <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">
     *         https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf</a>
     */
    SHA3_384(8, "SHA3-384", 384),

    /**
     * The SHA3-512 algorithm as defined by NIST FIPS 202.
     *
     * @see <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">
     *         https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf</a>
     */
    SHA3_512(9, "SHA3-512", 512);

    /**
     * Internal lookup table to provide {@code O(1)} time conversion of {@code id} to enumeration value.
     */
    private static final Map<Integer, HashAlgorithm> idMap = new HashMap<>();

    static {
        for (HashAlgorithm algorithm : HashAlgorithm.values()) {
            if (algorithm == NONE) {
                continue;
            }

            idMap.put(algorithm.id(), algorithm);
        }
    }

    /**
     * The number of bits in the hash value produced by the algorithm.
     */
    @Positive
    private final int bits;

    /**
     * The number of bytes in the hash value produced by the algorithm.
     */
    @Positive
    private final int bytes;

    /**
     * The name of the algorithm as specified by the standard Java Security documentation.
     *
     * @see <a href="https://docs.oracle.com/en/java/javase/14/docs/specs/security/standard-names.html">Java
     *         Security Standard Algorithm Names</a>
     */
    @NotNull
    private final String algorithmName;

    /**
     * A unique identifier for this algorithm. This identifier must remain constant for a given algorithm and must never
     * be reused by another algorithm.
     */
    private final int id;

    /**
     * Enumeration Constructor.
     *
     * @param id
     *         the unique identifier for this algorithm
     * @param algorithmName
     *         the standard name for this algorithm as specified by the Java Security documentation, not null
     * @param bits
     *         the number of bits in the hash value produced by this algorithm, positive and greater than zero
     */
    HashAlgorithm(final int id, @NotNull final String algorithmName, @Positive final int bits) {
        this.id = id;
        this.algorithmName = algorithmName;
        this.bits = bits;
        this.bytes = bits / Byte.SIZE;
    }

    /**
     * Lookup the enumeration value for the identifier specified by the {@code id} parameter. If no enumeration value
     * exists for the specified identifier then {@code null} will be returned.
     *
     * @param id
     *         the unique identifier of the algorithm
     * @return the enumeration value represented by the identifier or {@code null} if no enumeration value could be
     *         found for this identifier
     */
    public static HashAlgorithm valueOf(final int id) {
        if (!idMap.containsKey(id)) {
            return null;
        }

        return idMap.get(id);
    }

    /**
     * Gets the standard name of the algorithm as specified by the Java Security Standard Algorithm Names
     * documentation.
     *
     * @return the standard algorithm name
     * @see <a href="https://docs.oracle.com/en/java/javase/14/docs/specs/security/standard-names.html">Java
     *         Security Standard Algorithm Names</a>
     */
    public String algorithmName() {
        return algorithmName;
    }

    /**
     * Gets the number of bits in the hash value produced by this algorithm.
     *
     * @return the number of bits in the hash value
     */
    public int bits() {
        return bits;
    }

    /**
     * Gets the number of bytes in the hash value produced by this algorithm.
     *
     * @return the number of bytes in the hash value
     */
    public int bytes() {
        return bytes;
    }

    /**
     * Gets the unique identifier of this algorithm.
     *
     * @return the unique identifier
     */
    public int id() {
        return id;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public MessageDigest instance() {
        try {
            return MessageDigest.getInstance(algorithmName);
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptographyException(ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public MessageDigest instance(@NotNull final String provider) {
        try {
            return MessageDigest.getInstance(algorithmName, provider);
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            throw new CryptographyException(ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public MessageDigest instance(@NotNull final Provider provider) {
        try {
            return MessageDigest.getInstance(algorithmName, provider);
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptographyException(ex);
        }
    }
}
