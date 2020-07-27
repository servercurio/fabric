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

import java.util.HashMap;
import java.util.Map;
import javax.validation.constraints.NotNull;

/**
 * An enumeration of the standard cryptographic encryption algorithms along with their initialization
 * parameters.
 */
public enum CipherAlgorithm {
    /**
     * Represents no algorithm specified or an unknown algorithm was used.
     */
    NONE(0, "NONE", "NONE"),

    /**
     * The AES algorithm as defined by NIST FIPS 197.
     *
     * @see <a href="https://csrc.nist.gov/publications/fips/fips197/fips-197.pdf">
     *     https://csrc.nist.gov/publications/fips/fips197/fips-197.pdf</a>
     */
    AES(1, "AES", "AES"),

    /**
     * The ChaCha20 algorithm as defined by RFC-7539.
     *
     * @see <a href="https://tools.ietf.org/html/rfc7539">
     *     https://tools.ietf.org/html/rfc7539</a>
     */
    CHACHA20(2, "ChaCha20", "ChaCha20"),

    /**
     * The ChaCha20 with Poly1305 AEAD algorithm as defined by RFC-7539.
     *
     * @see <a href="https://tools.ietf.org/html/rfc7539">
     *     https://tools.ietf.org/html/rfc7539</a>
     */
    CHACHA20_POLY1305(3, "ChaCha20-Poly1305", "ChaCha20"),

    /**
     * The RSA algorithm as defined by RFC-8017.
     *
     * @see <a href="https://tools.ietf.org/html/rfc8017">
     *     https://tools.ietf.org/html/rfc8017</a>
     */
    RSA(4, "RSA", "RSA");

    /**
     * Internal lookup table to provide {@code O(1)} time conversion of {@code id} to enumeration value.
     */
    private static final Map<Integer, CipherAlgorithm> idMap = new HashMap<>();

    static {
        for (CipherAlgorithm algorithm : CipherAlgorithm.values()) {
            if (algorithm == NONE) {
                continue;
            }

            idMap.put(algorithm.id(), algorithm);
        }
    }

    /**
     * The name of the key generation algorithm as specified by the standard Java Security documentation.
     *
     * @see <a href="https://docs.oracle.com/en/java/javase/14/docs/specs/security/standard-names.html">Java
     *         Security Standard Algorithm Names</a>
     */
    @NotNull
    private final String keyAlgorithmName;

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
     * @param keyAlgorithmName
     *         the standard name for the key generation algorithm as specified by the Java Security documentation, not
     *         null
     */
    CipherAlgorithm(final int id, @NotNull final String algorithmName, @NotNull final String keyAlgorithmName) {
        this.id = id;
        this.algorithmName = algorithmName;
        this.keyAlgorithmName = keyAlgorithmName;
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
    public static CipherAlgorithm valueOf(final int id) {
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
     * Gets the unique identifier of this algorithm.
     *
     * @return the unique identifier
     */
    public int id() {
        return id;
    }

    /**
     * Gets the standard name of the key generation algorithm as specified by the Java Security Standard Algorithm Names
     * documentation.
     *
     * @return the standard algorithm name
     * @see <a href="https://docs.oracle.com/en/java/javase/14/docs/specs/security/standard-names.html">Java
     *         Security Standard Algorithm Names</a>
     */
    public String keyAlgorithmName() {
        return keyAlgorithmName;
    }

}
