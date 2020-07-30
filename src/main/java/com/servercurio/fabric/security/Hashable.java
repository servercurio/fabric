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

/**
 * Standard interface for classes that need to carry their own cryptographic {@link Hash} and may compute their own
 * hash. If the class does not compute it's own {@link Hash} then it should clearly document either how the hash should
 * be computed or reference an external utility used to compute the {@link Hash}.
 * <p>
 * Classes that compute their own {@link Hash} values can either implement this interface directly or extend {@link
 * AbstractHashable} which provides a reasonable default implementation of this interface.
 *
 * @author Nathan Klick
 * @see AbstractHashable
 */
public interface Hashable {

    /**
     * Gets the hash value or null if no hash value has been computed.
     *
     * @return the current hash value or null if no hash value has been computed
     */
    Hash getHash();

    /**
     * Sets the hash value to the one provided or clears the hash if the {@code hash} parameter is {@code null}.
     *
     * @param hash
     *         the hash value, may be null
     */
    void setHash(final Hash hash);

    /**
     * Returns true if this object has a valid hash. A valid hash is defined as a non-null reference that is not an
     * empty hash as defined by the {@link Hash#isEmpty()} method.
     *
     * @return true if this object has a valid, non-empty hash; otherwise false
     * @see Hash#isEmpty()
     */
    boolean hasHash();

}
