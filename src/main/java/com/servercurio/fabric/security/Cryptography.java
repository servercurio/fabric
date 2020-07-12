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
import com.servercurio.fabric.security.spi.MacProvider;
import com.servercurio.fabric.security.spi.MessageDigestProvider;
import com.servercurio.fabric.security.spi.SignatureProvider;
import com.servercurio.fabric.security.spi.SymmetricEncryptionProvider;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.Mac;

/**
 *
 */
public interface Cryptography extends AutoCloseable, MessageDigestProvider, SymmetricEncryptionProvider,
        SignatureProvider, MacProvider {

    /**
     * @return
     */
    static Cryptography getDefaultInstance() {
        return DefaultCryptographyImpl.getInstance();
    }

    /**
     * @return
     */
    static Cryptography newDefaultInstance() {
        return DefaultCryptographyImpl.newInstance();
    }

    /**
     * @param algorithm
     * @return
     */
    Cipher acquirePrimitive(final CipherTransformation algorithm);

    /**
     * @param algorithm
     * @return
     */
    Signature acquirePrimitive(final SignatureAlgorithm algorithm);

    /**
     * @param algorithm
     * @return
     */
    MessageDigest acquirePrimitive(final HashAlgorithm algorithm);

    /**
     * @param algorithm
     * @return
     */
    Mac acquirePrimitive(final MacAlgorithm algorithm);

}
