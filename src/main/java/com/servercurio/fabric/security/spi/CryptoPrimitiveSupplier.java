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

import com.servercurio.fabric.security.CryptographyException;
import java.security.Provider;

public interface CryptoPrimitiveSupplier<T> {

    /**
     * Creates an instance of the algorithm using the Java Cryptography Architecture and the default {@link Provider}
     * implementation.
     *
     * @return an instance of the algorithm implementation
     * @throws CryptographyException
     *         if an error occurs or the algorithm implementation was not available
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html">Java
     *         Cryptography Architecture</a>
     */
    T instance();

    /**
     * Creates an instance of the algorithm using the Java Cryptography Architecture and requesting the implementation
     * from the specified {@code provider}.
     *
     * @param provider
     *         the name of the provider from which to request the algorithm implementation, not null
     * @return an instance of the algorithm implementation
     * @throws CryptographyException
     *         if an error occurs, the algorithm implementation was not available, or the provider was not available
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html">Java
     *         Cryptography Architecture</a>
     */
    T instance(final String provider);

    /**
     * Creates an instance of the algorithm using the Java Cryptography Architecture and requesting the implementation
     * from the specified {@code provider}.
     *
     * @param provider
     *         the provider instance from which to request the algorithm implementation, not null
     * @return an instance of the algorithm implementation
     * @throws CryptographyException
     *         if an error occurs or the algorithm implementation was not available
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html">Java
     *         Cryptography Architecture</a>
     */
    T instance(final Provider provider);

}
