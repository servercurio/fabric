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
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Signature;
import java.util.HashMap;
import java.util.Map;
import javax.validation.constraints.NotNull;

import static com.servercurio.fabric.lang.Validators.throwIfArgumentIsNull;

/**
 * An enumeration of the standard cryptographic signature algorithms along with their initialization parameters.
 *
 * @author Nathan Klick
 */
public enum SignatureAlgorithm implements CryptoPrimitiveSupplier<Signature> {
    /**
     * Represents no algorithm specified or an unknown algorithm was used.
     */
    NONE(0, "NONE", "NONE"),

    /**
     * The RSA algorithm as defined by RFC-8017.
     *
     * @see <a href="https://tools.ietf.org/html/rfc8017">https://tools.ietf.org/html/rfc8017</a>
     */
    RSA(1, "NONEwithRSA", "RSA"),

    /**
     * The RSA with SHA-224 algorithm as defined by RFC-8017.
     *
     * @see <a href="https://tools.ietf.org/html/rfc8017">https://tools.ietf.org/html/rfc8017</a>
     */
    RSA_SHA_224(2, "SHA224withRSA", "RSA"),

    /**
     * The RSA with SHA-256 algorithm as defined by RFC-8017.
     *
     * @see <a href="https://tools.ietf.org/html/rfc8017">https://tools.ietf.org/html/rfc8017</a>
     */
    RSA_SHA_256(3, "SHA256withRSA", "RSA"),

    /**
     * The RSA with SHA-384 algorithm as defined by RFC-8017.
     *
     * @see <a href="https://tools.ietf.org/html/rfc8017">https://tools.ietf.org/html/rfc8017</a>
     */
    RSA_SHA_384(4, "SHA384withRSA", "RSA"),

    /**
     * The RSA with SHA-512 algorithm as defined by RFC-8017.
     *
     * @see <a href="https://tools.ietf.org/html/rfc8017">https://tools.ietf.org/html/rfc8017</a>
     */
    RSA_SHA_512(5, "SHA512withRSA", "RSA"),

    /**
     * The RSA with SHA3-224 algorithm as defined by RFC-8017.
     *
     * @see <a href="https://tools.ietf.org/html/rfc8017">https://tools.ietf.org/html/rfc8017</a>
     */
    RSA_SHA3_224(6, "SHA3-224withRSA", "RSA"),

    /**
     * The RSA with SHA3-256 algorithm as defined by RFC-8017.
     *
     * @see <a href="https://tools.ietf.org/html/rfc8017">https://tools.ietf.org/html/rfc8017</a>
     */
    RSA_SHA3_256(7, "SHA3-256withRSA", "RSA"),

    /**
     * The RSA with SHA3-384 algorithm as defined by RFC-8017.
     *
     * @see <a href="https://tools.ietf.org/html/rfc8017">https://tools.ietf.org/html/rfc8017</a>
     */
    RSA_SHA3_384(8, "SHA3-384withRSA", "RSA"),

    /**
     * The RSA with SHA3-512 algorithm as defined by RFC-8017.
     *
     * @see <a href="https://tools.ietf.org/html/rfc8017">https://tools.ietf.org/html/rfc8017</a>
     */
    RSA_SHA3_512(9, "SHA3-512withRSA", "RSA"),

    /**
     * The DSA algorithm as defined by NIST FIPS 186-2.
     *
     * @see <a href="https://csrc.nist.gov/publications/fips/archive/fips186-2/fips186-2.pdf">
     *         https://csrc.nist.gov/publications/fips/archive/fips186-2/fips186-2.pdf</a>
     */
    DSA(10, "NONEwithDSA", "DSA"),

    /**
     * The DSA with SHA-224 algorithm as defined by NIST FIPS 186-4.
     *
     * @see <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf">
     *         https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf</a>
     */
    DSA_SHA_224(11, "SHA224withDSA", "DSA"),

    /**
     * The DSA with SHA-256 algorithm as defined by NIST FIPS 186-4.
     *
     * @see <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf">
     *         https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf</a>
     */
    DSA_SHA_256(12, "SHA256withDSA", "DSA"),

    /**
     * The DSA with SHA-384 algorithm as defined by NIST FIPS 186-4.
     *
     * @see <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf">
     *         https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf</a>
     */
    DSA_SHA_384(13, "SHA384withDSA", "DSA"),

    /**
     * The DSA with SHA-512 algorithm as defined by NIST FIPS 186-4.
     *
     * @see <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf">
     *         https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf</a>
     */
    DSA_SHA_512(14, "SHA512withDSA", "DSA"),

    /**
     * The DSA with SHA3-224 algorithm as defined by NIST FIPS 186-4.
     *
     * @see <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf">
     *         https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf</a>
     */
    DSA_SHA3_224(15, "SHA3-224withDSA", "DSA"),

    /**
     * The DSA with SHA3-256 algorithm as defined by NIST FIPS 186-4.
     *
     * @see <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf">
     *         https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf</a>
     */
    DSA_SHA3_256(16, "SHA3-256withDSA", "DSA"),

    /**
     * The DSA with SHA3-384 algorithm as defined by NIST FIPS 186-4.
     *
     * @see <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf">
     *         https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf</a>
     */
    DSA_SHA3_384(17, "SHA3-384withDSA", "DSA"),

    /**
     * The DSA with SHA3-512 algorithm as defined by NIST FIPS 186-4.
     *
     * @see <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf">
     *         https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf</a>
     */
    DSA_SHA3_512(18, "SHA3-512withDSA", "DSA"),

    /**
     * The ECDSA algorithm as defined by ANSI X9.62.
     *
     * @see <a href="http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.202.2977&amp;rep=rep1&amp;type=pdf">
     *         http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.202.2977&amp;rep=rep1&amp;type=pdf</a>
     */
    ECDSA(19, "NONEwithECDSA", "EC"),

    /**
     * The ECDSA with SHA-224 algorithm as defined by ANSI X9.62.
     *
     * @see <a href="http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.202.2977&amp;rep=rep1&amp;type=pdf">
     *         http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.202.2977&amp;rep=rep1&amp;type=pdf</a>
     */
    ECDSA_SHA_224(20, "SHA224withECDSA", "EC"),

    /**
     * The ECDSA with SHA-256 algorithm as defined by ANSI X9.62.
     *
     * @see <a href="http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.202.2977&amp;rep=rep1&amp;type=pdf">
     *         http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.202.2977&amp;rep=rep1&amp;type=pdf</a>
     */
    ECDSA_SHA_256(21, "SHA256withECDSA", "EC"),

    /**
     * The ECDSA with SHA-384 algorithm as defined by ANSI X9.62.
     *
     * @see <a href="http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.202.2977&amp;rep=rep1&amp;type=pdf">
     *         http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.202.2977&amp;amp;rep=rep1&amp;amp;type=pdf</a>
     */
    ECDSA_SHA_384(22, "SHA384withECDSA", "EC"),

    /**
     * The ECDSA with SHA-512 algorithm as defined by ANSI X9.62.
     *
     * @see <a href="http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.202.2977&amp;amp;rep=rep1&amp;amp;type=pdf">
     *         http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.202.2977&amp;rep=rep1&amp;type=pdf</a>
     */
    ECDSA_SHA_512(23, "SHA512withECDSA", "EC"),

    /**
     * The ECDSA with SHA3-224 algorithm as defined by ANSI X9.62.
     *
     * @see <a href="http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.202.2977&amp;rep=rep1&amp;type=pdf">
     *         http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.202.2977&amp;rep=rep1&amp;type=pdf</a>
     */
    ECDSA_SHA3_224(24, "SHA3-224withECDSA", "EC"),

    /**
     * The ECDSA with SHA3-256 algorithm as defined by ANSI X9.62.
     *
     * @see <a href="http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.202.2977&amp;rep=rep1&amp;type=pdf">
     *         http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.202.2977&amp;rep=rep1&amp;type=pdf</a>
     */
    ECDSA_SHA3_256(25, "SHA3-256withECDSA", "EC"),

    /**
     * The ECDSA with SHA3-384 algorithm as defined by ANSI X9.62.
     *
     * @see <a href="http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.202.2977&amp;rep=rep1&amp;type=pdf">
     *         http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.202.2977&amp;rep=rep1&amp;type=pdf</a>
     */
    ECDSA_SHA3_384(26, "SHA3-384withECDSA", "EC"),

    /**
     * The ECDSA with SHA3-512 algorithm as defined by ANSI X9.62.
     *
     * @see <a href="http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.202.2977&amp;rep=rep1&amp;type=pdf">
     *         http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.202.2977&amp;rep=rep1&amp;type=pdf</a>
     */
    ECDSA_SHA3_512(27, "SHA3-512withECDSA", "EC");

    /**
     * The {@code algorithmName} field name represented as a string value.
     */
    private static final String ALGORITHM_NAME_FIELD = "algorithmName";

    /**
     * The {@code keyAlgorithmName} field name represented as a string value.
     */
    private static final String KEY_ALGORITHM_NAME_FIELD = "keyAlgorithmName";

    /**
     * The {@code provider} parameter name represented as a string value.
     */
    private static final String PROVIDER_PARAM = "provider";

    /**
     * Internal lookup table to provide {@code O(1)} time conversion of {@code id} to enumeration value.
     */
    private static final Map<Integer, SignatureAlgorithm> idMap = new HashMap<>();


    static {
        for (SignatureAlgorithm algorithm : SignatureAlgorithm.values()) {
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
    SignatureAlgorithm(final int id, @NotNull final String algorithmName, @NotNull final String keyAlgorithmName) {
        throwIfArgumentIsNull(algorithmName, ALGORITHM_NAME_FIELD);
        throwIfArgumentIsNull(keyAlgorithmName, KEY_ALGORITHM_NAME_FIELD);

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
    public static SignatureAlgorithm valueOf(final int id) {
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
     * {@inheritDoc}
     */
    @Override
    public Signature instance() {
        try {
            return Signature.getInstance(algorithmName);
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptographyException(ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Signature instance(@NotNull final String provider) {
        throwIfArgumentIsNull(provider, PROVIDER_PARAM);

        try {
            return Signature.getInstance(algorithmName, provider);
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            throw new CryptographyException(ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Signature instance(@NotNull final Provider provider) {
        throwIfArgumentIsNull(provider, PROVIDER_PARAM);

        try {
            return Signature.getInstance(algorithmName, provider);
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptographyException(ex);
        }
    }
}
