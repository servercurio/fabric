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
import com.servercurio.fabric.security.spi.DigestProvider;
import com.servercurio.fabric.security.spi.SignatureProvider;
import com.servercurio.fabric.security.spi.EncryptionProvider;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.Mac;

/**
 *
 */
public interface Cryptography extends AutoCloseable {

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
    Cipher primitive(final CipherTransformation algorithm);

    /**
     * @param algorithm
     * @return
     */
    Signature primitive(final SignatureAlgorithm algorithm);

    /**
     * @param algorithm
     * @return
     */
    MessageDigest primitive(final HashAlgorithm algorithm);

    /**
     * @param algorithm
     * @return
     */
    Mac primitive(final MacAlgorithm algorithm);

    /**
     *
     * @return
     */
    SecureRandom random();

    DigestProvider digest();

    MacProvider mac();

    SignatureProvider signature();

    EncryptionProvider encryption();




}
