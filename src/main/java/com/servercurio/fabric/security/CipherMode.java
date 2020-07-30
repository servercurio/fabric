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
 * An enumeration of the standard cryptographic encryption algorithm modes along with their initialization parameters.
 *
 * @author Nathan Klick
 */
public enum CipherMode {
    /**
     * Represents no mode specified or an unknown mode was used.
     */
    NONE(0, "NONE"),

    /**
     * The CBC mode as defined by NIST FIPS 81.
     *
     * @see <a href="https://csrc.nist.gov/publications/fips/fips81/fips81.htm">
     *         https://csrc.nist.gov/publications/fips/fips81/fips81.htm</a>
     */
    CBC(1, "CBC"),

    /**
     * The CCM mode as defined by NIST Special Publication SP 800-38C.
     *
     * @see <a href="https://csrc.nist.gov/publications/nistpubs/800-38C/SP800-38C_updated-July20_2007.pdf">
     *         https://csrc.nist.gov/publications/nistpubs/800-38C/SP800-38C_updated-July20_2007.pdf</a>
     */
    CCM(2, "CCM"),

    /**
     * The CFB mode as defined by NIST FIPS 81.
     *
     * @see <a href="https://csrc.nist.gov/publications/fips/fips81/fips81.htm">
     *         https://csrc.nist.gov/publications/fips/fips81/fips81.htm</a>
     */
    CFB(3, "CFB"),

    /**
     * The CFB 8-bit mode as defined by NIST FIPS 81.
     *
     * @see <a href="https://csrc.nist.gov/publications/fips/fips81/fips81.htm">
     *         https://csrc.nist.gov/publications/fips/fips81/fips81.htm</a>
     */
    CFB8(4, "CFB8"),

    /**
     * The CTR mode as defined by NIST FIPS 81.
     *
     * @see <a href="https://csrc.nist.gov/publications/fips/fips81/fips81.htm">
     *         https://csrc.nist.gov/publications/fips/fips81/fips81.htm</a>
     */
    CTR(5, "CTR"),

    /**
     * The CTS mode as defined by Applied Cryptography (Second Edition) by Bruce Schneier.
     *
     * @see <a href="https://www.schneier.com/books/applied_cryptography/">
     *         https://www.schneier.com/books/applied_cryptography/</a>
     */
    CTS(6, "CTS"),

    /**
     * The ECB mode as defined by NIST FIPS 81.
     *
     * @see <a href="https://csrc.nist.gov/publications/fips/fips81/fips81.htm">
     *         https://csrc.nist.gov/publications/fips/fips81/fips81.htm</a>
     */
    ECB(7, "ECB"),

    /**
     * The GCM mode as defined by NIST Special Publication SP 800-38D.
     *
     * @see <a href="https://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf">
     *         https://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf</a>
     */
    GCM(8, "GCM"),

    /**
     * The OFB mode as defined by NIST FIPS 81.
     *
     * @see <a href="https://csrc.nist.gov/publications/fips/fips81/fips81.htm">
     *         https://csrc.nist.gov/publications/fips/fips81/fips81.htm</a>
     */
    OFB(9, "OFB"),

    /**
     * The OFB 8-bit mode as defined by NIST FIPS 81.
     *
     * @see <a href="https://csrc.nist.gov/publications/fips/fips81/fips81.htm">
     *         https://csrc.nist.gov/publications/fips/fips81/fips81.htm</a>
     */
    OFB8(10, "OFB8");

    /**
     * Internal lookup table to provide {@code O(1)} time conversion of {@code id} to enumeration value.
     */
    private static final Map<Integer, CipherMode> idMap = new HashMap<>();

    static {
        for (CipherMode algorithm : CipherMode.values()) {
            if (algorithm == NONE) {
                continue;
            }

            idMap.put(algorithm.id(), algorithm);
        }
    }

    /**
     * The name of the algorithm mode as specified by the standard Java Security documentation.
     *
     * @see <a href="https://docs.oracle.com/en/java/javase/14/docs/specs/security/standard-names.html">Java
     *         Security Standard Algorithm Names</a>
     */
    @NotNull
    private final String modeName;

    /**
     * A unique identifier for this algorithm mode. This identifier must remain constant for a given algorithm mode and
     * must never be reused by another algorithm mode.
     */
    private final int id;

    /**
     * Enumeration Constructor.
     *
     * @param id
     *         the unique identifier for this algorithm mode
     * @param modeName
     *         the standard name for this algorithm mode as specified by the Java Security documentation, not null
     */
    CipherMode(final int id, @NotNull final String modeName) {
        this.id = id;
        this.modeName = modeName;
    }

    /**
     * Lookup the enumeration value for the identifier specified by the {@code id} parameter. If no enumeration value
     * exists for the specified identifier then {@code null} will be returned.
     *
     * @param id
     *         the unique identifier of the algorithm mode
     * @return the enumeration value represented by the identifier or {@code null} if no enumeration value could be
     *         found for this identifier
     */
    public static CipherMode valueOf(final int id) {
        if (!idMap.containsKey(id)) {
            return null;
        }

        return idMap.get(id);
    }

    /**
     * Gets the unique identifier of this algorithm mode.
     *
     * @return the unique identifier
     */
    public int id() {
        return id;
    }

    /**
     * Gets the standard name of the mode as specified by the Java Security Standard Algorithm Names documentation.
     *
     * @return the standard algorithm mode name
     * @see <a href="https://docs.oracle.com/en/java/javase/14/docs/specs/security/standard-names.html">Java
     *         Security Standard Algorithm Names</a>
     */
    public String modeName() {
        return modeName;
    }
}
