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
import com.servercurio.fabric.security.spi.SignatureProvider;
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
     * @return
     */
    DigestProvider digest();

    /**
     * @return
     */
    EncryptionProvider encryption();

    /**
     * @return
     */
    MacProvider mac();

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
     * @return
     */
    SecureRandom random();

    /**
     * @param left
     * @param right
     * @return
     */
    default boolean secureEquals(final char[] left, final char[] right) {
        int diff = left.length ^ right.length;
        for (int i = 0; i < left.length && i < right.length; i++) {
            diff |= left[i] ^ right[i];
        }
        return diff == 0;
    }

    /**
     * @param left
     * @param right
     * @return
     */
    default boolean secureEquals(final byte[] left, final byte[] right) {
        int diff = left.length ^ right.length;
        for (int i = 0; i < left.length && i < right.length; i++) {
            diff |= left[i] ^ right[i];
        }
        return diff == 0;
    }

    /**
     * @param left
     * @param right
     * @return
     */
    default boolean secureEquals(final int[] left, final int[] right) {
        int diff = left.length ^ right.length;
        for (int i = 0; i < left.length && i < right.length; i++) {
            diff |= left[i] ^ right[i];
        }
        return diff == 0;
    }

    /**
     * @param left
     * @param right
     * @return
     */
    default boolean secureEquals(final long[] left, final long[] right) {
        int diff = left.length ^ right.length;
        for (int i = 0; i < left.length && i < right.length; i++) {
            diff |= left[i] ^ right[i];
        }
        return diff == 0;
    }

    /**
     * @return
     */
    SignatureProvider signature();

}
