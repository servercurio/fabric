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
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Mac;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Positive;

import static com.servercurio.fabric.lang.Validators.throwIfArgumentIsNull;

/**
 * An enumeration of the standard cryptographic hash-based message authentication algorithms along with their
 * initialization parameters.
 *
 * @author Nathan Klick
 */
public enum MacAlgorithm implements CryptoPrimitiveSupplier<Mac> {
    /**
     * Represents no algorithm specified or an unknown algorithm was used.
     */
    NONE(0, "NONE", HashAlgorithm.NONE),

    /**
     * The HMAC SHA-224 algorithm as defined by RFC-2104.
     *
     * @see <a href="https://tools.ietf.org/html/rfc2104">https://tools.ietf.org/html/rfc2104</a>
     */
    HMAC_SHA_224(1, "HmacSHA224", HashAlgorithm.SHA_224),

    /**
     * The HMAC SHA-256 algorithm as defined by RFC-2104.
     *
     * @see <a href="https://tools.ietf.org/html/rfc2104">https://tools.ietf.org/html/rfc2104</a>
     */
    HMAC_SHA_256(2, "HmacSHA256", HashAlgorithm.SHA_256),

    /**
     * The HMAC SHA-384 algorithm as defined by RFC-2104.
     *
     * @see <a href="https://tools.ietf.org/html/rfc2104">https://tools.ietf.org/html/rfc2104</a>
     */
    HMAC_SHA_384(3, "HmacSHA384", HashAlgorithm.SHA_384),

    /**
     * The HMAC SHA-512 algorithm as defined by RFC-2104.
     *
     * @see <a href="https://tools.ietf.org/html/rfc2104">https://tools.ietf.org/html/rfc2104</a>
     */
    HMAC_SHA_512(4, "HmacSHA512", HashAlgorithm.SHA_512),

    /**
     * The HMAC SHA3-224 algorithm as defined by RFC-2104.
     *
     * @see <a href="https://tools.ietf.org/html/rfc2104">https://tools.ietf.org/html/rfc2104</a>
     */
    HMAC_SHA3_224(5, "HmacSHA3-224", HashAlgorithm.SHA3_224),

    /**
     * The HMAC SHA3-256 algorithm as defined by RFC-2104.
     *
     * @see <a href="https://tools.ietf.org/html/rfc2104">https://tools.ietf.org/html/rfc2104</a>
     */
    HMAC_SHA3_256(6, "HmacSHA3-256", HashAlgorithm.SHA3_256),

    /**
     * The HMAC SHA3-384 algorithm as defined by RFC-2104.
     *
     * @see <a href="https://tools.ietf.org/html/rfc2104">https://tools.ietf.org/html/rfc2104</a>
     */
    HMAC_SHA3_384(7, "HmacSHA3-384", HashAlgorithm.SHA3_384),

    /**
     * The HMAC SHA3-512 algorithm as defined by RFC-2104.
     *
     * @see <a href="https://tools.ietf.org/html/rfc2104">https://tools.ietf.org/html/rfc2104</a>
     */
    HMAC_SHA3_512(8, "HmacSHA3-512", HashAlgorithm.SHA3_512);

    /**
     * The {@code algorithmName} field name represented as a string value.
     */
    private static final String ALGORITHM_NAME_FIELD = "algorithmName";

    /**
     * The {@code keyAlgorithmName} field name represented as a string value.
     */
    private static final String KEY_ALGORITHM_NAME_FIELD = "keyAlgorithmName";

    /**
     * The {@code hashAlgorithm} field name represented as a string value.
     */
    private static final String HASH_ALGORITHM_FIELD = "hashAlgorithm";

    /**
     * The {@code provider} parameter name represented as a string value.
     */
    private static final String PROVIDER_PARAM = "provider";

    /**
     * Internal lookup table to provide {@code O(1)} time conversion of {@code id} to enumeration value.
     */
    private static final Map<Integer, MacAlgorithm> idMap = new HashMap<>();

    static {
        for (MacAlgorithm algorithm : MacAlgorithm.values()) {
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
     * The underlying hash algorithm used by this message authentication algorithm.
     */
    @NotNull
    private final HashAlgorithm hashAlgorithm;

    /**
     * Enumeration Constructor.
     *
     * @param id
     *         the unique identifier for this algorithm
     * @param algorithmName
     *         the standard name for this algorithm as specified by the Java Security documentation, not null
     * @param hashAlgorithm
     *         the underlying hash algorithm used by this message authentication algorithm
     */
    MacAlgorithm(final int id, @NotNull final String algorithmName, @NotNull final HashAlgorithm hashAlgorithm) {
        throwIfArgumentIsNull(algorithmName, ALGORITHM_NAME_FIELD);
        throwIfArgumentIsNull(hashAlgorithm, HASH_ALGORITHM_FIELD);

        this.id = id;
        this.algorithmName = algorithmName;
        this.hashAlgorithm = hashAlgorithm;
        this.bits = hashAlgorithm.bits();
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
    public static MacAlgorithm valueOf(final int id) {
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
     * Gets the underlying hash algorithm used by this message authentication algorithm.
     *
     * @return the underlying hash algorithm
     */
    public HashAlgorithm hashAlgorithm() {
        return hashAlgorithm;
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
    public Mac instance() {
        try {
            return Mac.getInstance(algorithmName);
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptographyException(ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Mac instance(@NotNull final String provider) {
        throwIfArgumentIsNull(provider, PROVIDER_PARAM);

        try {
            return Mac.getInstance(algorithmName, provider);
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            throw new CryptographyException(ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Mac instance(@NotNull final Provider provider) {
        throwIfArgumentIsNull(provider, PROVIDER_PARAM);

        try {
            return Mac.getInstance(algorithmName, provider);
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptographyException(ex);
        }
    }
}
