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

import static com.servercurio.fabric.lang.Validators.throwIfArgIsNull;

/**
 * An enumeration of the standard cryptographic encryption algorithms along with their initialization parameters.
 *
 * @author Nathan Klick
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
     *         https://csrc.nist.gov/publications/fips/fips197/fips-197.pdf</a>
     */
    AES(1, "AES", "AES"),

    /**
     * The AES algorithm as defined by NIST FIPS 197.
     *
     * @see <a href="https://csrc.nist.gov/publications/fips/fips197/fips-197.pdf">
     *         https://csrc.nist.gov/publications/fips/fips197/fips-197.pdf</a>
     */
    AES_128(2, "AES_128", "AES"),

    /**
     * The AES algorithm as defined by NIST FIPS 197.
     *
     * @see <a href="https://csrc.nist.gov/publications/fips/fips197/fips-197.pdf">
     *         https://csrc.nist.gov/publications/fips/fips197/fips-197.pdf</a>
     */
    AES_192(3, "AES_192", "AES"),

    /**
     * The AES algorithm as defined by NIST FIPS 197.
     *
     * @see <a href="https://csrc.nist.gov/publications/fips/fips197/fips-197.pdf">
     *         https://csrc.nist.gov/publications/fips/fips197/fips-197.pdf</a>
     */
    AES_256(4, "AES_256", "AES"),

    /**
     * The ChaCha20 algorithm as defined by RFC-7539.
     *
     * @see <a href="https://tools.ietf.org/html/rfc7539">
     *         https://tools.ietf.org/html/rfc7539</a>
     */
    CHACHA20(5, "ChaCha20", "ChaCha20"),

    /**
     * The ChaCha20 with Poly1305 AEAD algorithm as defined by RFC-7539.
     *
     * @see <a href="https://tools.ietf.org/html/rfc7539">
     *         https://tools.ietf.org/html/rfc7539</a>
     */
    CHACHA20_POLY1305(6, "ChaCha20-Poly1305", "ChaCha20"),

    /**
     * The RSA algorithm as defined by RFC-8017.
     *
     * @see <a href="https://tools.ietf.org/html/rfc8017">
     *         https://tools.ietf.org/html/rfc8017</a>
     */
    RSA(7, "RSA", "RSA");

    /**
     * The {@code algorithmName} field name represented as a string value.
     */
    private static final String ALGORITHM_NAME_FIELD = "algorithmName";

    /**
     * The {@code keyAlgorithmName} field name represented as a string value.
     */
    private static final String KEY_ALGORITHM_NAME_FIELD = "keyAlgorithmName";


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
     * The name of the JCE provider that supplies this algorithm implementation.
     *
     * @see <a href="https://docs.oracle.com/en/java/javase/14/security/oracle-providers.html">Orcale JCE
     *         Providers</a>
     */
    private final String providerName;

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
    CipherAlgorithm(final int id, @NotNull final String algorithmName, final @NotNull String keyAlgorithmName) {
        this(id, algorithmName, keyAlgorithmName, null);
    }

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
     * @param providerName
     *         the standard name of the JCE provider that supplies this algorithm implementation, may be null
     */
    CipherAlgorithm(final int id, @NotNull final String algorithmName, @NotNull final String keyAlgorithmName,
                    final String providerName) {
        throwIfArgIsNull(algorithmName, ALGORITHM_NAME_FIELD);
        throwIfArgIsNull(keyAlgorithmName, KEY_ALGORITHM_NAME_FIELD);

        this.id = id;
        this.algorithmName = algorithmName;
        this.keyAlgorithmName = keyAlgorithmName;
        this.providerName = providerName;
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

    /**
     * Gets the standard name of the JCE provider that supplies this algorithm implementation.
     *
     * @return the standard JCE provider name, may be null
     * @see <a href="https://docs.oracle.com/en/java/javase/14/security/oracle-providers.html">Oracle JCE
     *         Providers</a>
     */
    public String providerName() {
        return providerName;
    }

}
