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

public enum MacAlgorithm implements CryptoPrimitiveSupplier<Mac> {
    NONE(0, "NONE", HashAlgorithm.NONE),
    HMAC_SHA_224(1, "HmacSHA224", HashAlgorithm.SHA_224),
    HMAC_SHA_256(2, "HmacSHA256", HashAlgorithm.SHA_256),
    HMAC_SHA_384(3, "HmacSHA384", HashAlgorithm.SHA_384),
    HMAC_SHA_512(4, "HmacSHA512", HashAlgorithm.SHA_512),
    HMAC_SHA3_224(5, "HmacSHA3-224", HashAlgorithm.SHA3_224),
    HMAC_SHA3_256(6, "HmacSHA3-256", HashAlgorithm.SHA3_256),
    HMAC_SHA3_384(7, "HmacSHA3-384", HashAlgorithm.SHA3_384),
    HMAC_SHA3_512(8, "HmacSHA3-512", HashAlgorithm.SHA3_512);


    private static final Map<Integer, MacAlgorithm> idMap = new HashMap<>();

    static {
        for (MacAlgorithm algorithm : MacAlgorithm.values()) {
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
    private final HashAlgorithm hashAlgorithm;

    MacAlgorithm(final int id, final String algorithmName, final HashAlgorithm hashAlgorithm) {
        this.id = id;
        this.algorithmName = algorithmName;
        this.hashAlgorithm = hashAlgorithm;
        this.bits = hashAlgorithm.bits();
        this.bytes = bits / Byte.SIZE;
    }

    public static MacAlgorithm valueOf(final int id) {
        if (!idMap.containsKey(id)) {
            return null;
        }

        return idMap.get(id);
    }

    public HashAlgorithm hashAlgorithm() {
        return hashAlgorithm;
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

    public Mac instance() {
        try {
            return Mac.getInstance(algorithmName);
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptographyException(ex);
        }
    }

    public Mac instance(final String provider) {
        try {
            return Mac.getInstance(algorithmName, provider);
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            throw new CryptographyException(ex);
        }
    }

    public Mac instance(final Provider provider) {
        try {
            return Mac.getInstance(algorithmName, provider);
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptographyException(ex);
        }
    }
}
