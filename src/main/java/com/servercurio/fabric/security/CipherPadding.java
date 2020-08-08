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

import static com.servercurio.fabric.lang.Validators.throwIfArgumentIsNull;

/**
 * An enumeration of the standard cryptographic encryption padding modes along with their initialization parameters.
 *
 * @author Nathan Klick
 */
public enum CipherPadding {
    /**
     * Represents no padding specified or an unknown padding was used.
     */
    NONE(0, "NoPadding"),

    /**
     * The RSA OAEP padding as defined by RFC-8017.
     *
     * @see <a href="https://tools.ietf.org/html/rfc8017">https://tools.ietf.org/html/rfc8017</a>
     */
    OAEP(1, "OAEPPadding"),

    /**
     * The PKCS1 padding as defined by RFC-8017.
     *
     * @see <a href="https://tools.ietf.org/html/rfc8017">https://tools.ietf.org/html/rfc8017</a>
     */
    PKCS1(2, "PKCS1Padding"),

    /**
     * The PKCS5 padding as defined by RFC-8018.
     *
     * @see <a href="https://tools.ietf.org/html/rfc8018">https://tools.ietf.org/html/rfc8018</a>
     */
    PKCS5(3, "PKCS5Padding");

    /**
     * The {@code paddingName} field name represented as a string value.
     */
    private static final String PADDING_NAME_FIELD = "paddingName";


    /**
     * Internal lookup table to provide {@code O(1)} time conversion of {@code id} to enumeration value.
     */
    private static final Map<Integer, CipherPadding> idMap = new HashMap<>();

    static {
        for (CipherPadding algorithm : CipherPadding.values()) {
            if (algorithm == NONE) {
                continue;
            }

            idMap.put(algorithm.id(), algorithm);
        }
    }

    /**
     * The name of the padding mode as specified by the standard Java Security documentation.
     *
     * @see <a href="https://docs.oracle.com/en/java/javase/14/docs/specs/security/standard-names.html">Java
     *         Security Standard Algorithm Names</a>
     */
    @NotNull
    private final String paddingName;

    /**
     * A unique identifier for this padding mode. This identifier must remain constant for a given padding mode and must
     * never be reused by another padding mode.
     */
    private final int id;

    /**
     * Enumeration Constructor.
     *
     * @param id
     *         the unique identifier for this padding mode
     * @param paddingName
     *         the standard name for this padding mode as specified by the Java Security documentation, not null
     */
    CipherPadding(final int id, @NotNull final String paddingName) {
        throwIfArgumentIsNull(paddingName, PADDING_NAME_FIELD);

        this.id = id;
        this.paddingName = paddingName;
    }

    /**
     * Lookup the enumeration value for the identifier specified by the {@code id} parameter. If no enumeration value
     * exists for the specified identifier then {@code null} will be returned.
     *
     * @param id
     *         the unique identifier of the padding mode
     * @return the enumeration value represented by the identifier or {@code null} if no enumeration value could be
     *         found for this identifier
     */
    public static CipherPadding valueOf(final int id) {
        if (!idMap.containsKey(id)) {
            return null;
        }

        return idMap.get(id);
    }

    /**
     * Gets the unique identifier of this padding mode.
     *
     * @return the unique identifier
     */
    public int id() {
        return id;
    }

    /**
     * Gets the standard name of the padding mode as specified by the Java Security Standard Algorithm Names
     * documentation.
     *
     * @return the standard padding mode name
     * @see <a href="https://docs.oracle.com/en/java/javase/14/docs/specs/security/standard-names.html">Java
     *         Security Standard Algorithm Names</a>
     */
    public String paddingName() {
        return paddingName;
    }
}
