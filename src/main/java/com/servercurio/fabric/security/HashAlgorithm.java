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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.util.HashMap;
import java.util.Map;

public enum HashAlgorithm implements CryptoPrimitiveSupplier<MessageDigest> {
    NONE(0, "NONE", 0),
    SHA_224(1, "SHA-224", 224),
    SHA_256(2, "SHA-256", 256),
    SHA_384(3, "SHA-384", 384),
    SHA_512(4, "SHA-512", 512),
    SHA3_224(5, "SHA3-224", 224),
    SHA3_256(6, "SHA3-256", 256),
    SHA3_384(7, "SHA3-384", 384),
    SHA3_512(8, "SHA3-512", 512),
    SHA1(9, "SHA-1", 160);

    private static final Map<Integer, HashAlgorithm> idMap = new HashMap<>();

    static {
        for (HashAlgorithm algorithm : HashAlgorithm.values()) {
            if (algorithm == NONE) {
                continue;
            }

            idMap.put(algorithm.id(), algorithm);
        }
    }

    private final int bits;
    private final int bytes;
    private final String algorithmName;
    private final int id;

    HashAlgorithm(final int id, final String algorithmName, final int bits) {
        this.id = id;
        this.algorithmName = algorithmName;
        this.bits = bits;
        this.bytes = bits / Byte.SIZE;
    }

    public static HashAlgorithm valueOf(final int id) {
        if (!idMap.containsKey(id)) {
            return null;
        }

        return idMap.get(id);
    }

    public String algorithmName() {
        return algorithmName;
    }

    public int bits() {
        return bits;
    }

    public int bytes() {
        return bytes;
    }

    public int id() {
        return id;
    }

    public MessageDigest instance() {
        try {
            return MessageDigest.getInstance(algorithmName);
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptographyException(ex);
        }
    }

    public MessageDigest instance(final String provider) {
        try {
            return MessageDigest.getInstance(algorithmName, provider);
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            throw new CryptographyException(ex);
        }
    }

    public MessageDigest instance(final Provider provider) {
        try {
            return MessageDigest.getInstance(algorithmName, provider);
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptographyException(ex);
        }
    }
}
