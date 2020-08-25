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
import com.servercurio.fabric.security.spi.PrimitiveProvider;
import com.servercurio.fabric.security.spi.SignatureProvider;
import java.util.ServiceLoader;

/**
 * Provides the {@code Fabric Unified Cryptography API} primary entry-point. The core API is broken down into multiple
 * provider interfaces. The providers encapsulate the discrete cryptographic functions. All implementors of the {@link
 * Cryptography} interface must provide implementations for the providers listed below:
 *
 * <p>
 * <ul>
 *     <li>{@link PrimitiveProvider}</li>
 *     <li>{@link DigestProvider}</li>
 *     <li>{@link MacProvider}</li>
 *     <li>{@link EncryptionProvider}</li>
 *     <li>{@link SignatureProvider}</li>
 * </ul>
 *
 * @author Nathan Klick
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
        return ServiceLoader.load(Cryptography.class).findFirst().orElseGet(DefaultCryptographyImpl::newInstance);
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
     * Provides all the cryptographic digital signature functionality.
     *
     * @return the provider associated with this {@link Cryptography} instance, not null
     */
    SignatureProvider signature();

    /**
     * Provides all the cryptographic primitive functionality.
     *
     * @return the provider associated with this {@link Cryptography} instance, not null
     */
    PrimitiveProvider primitives();

    /**
     * {@inheritDoc}
     */
    @Override
    void close();
}
