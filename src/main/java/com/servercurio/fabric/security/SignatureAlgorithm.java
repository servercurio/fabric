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
import java.security.Signature;
import java.util.HashMap;
import java.util.Map;

public enum SignatureAlgorithm implements CryptoPrimitiveSupplier<Signature> {
    NONE(0, "NONE", "NONE"),
    RSA(1, "NONEwithRSA", "RSA"),
    RSA_SHA_224(2, "SHA224withRSA", "RSA"),
    RSA_SHA_256(3, "SHA256withRSA", "RSA"),
    RSA_SHA_384(4, "SHA384withRSA", "RSA"),
    RSA_SHA_512(5, "SHA512withRSA", "RSA"),
    RSA_SHA3_224(6, "SHA3-224withRSA", "RSA"),
    RSA_SHA3_256(7, "SHA3-256withRSA", "RSA"),
    RSA_SHA3_384(8, "SHA3-384withRSA", "RSA"),
    RSA_SHA3_512(9, "SHA3-512withRSA", "RSA"),
    DSA(10, "NONEwithDSA", "DSA"),
    DSA_SHA_224(11, "SHA224withDSA", "DSA"),
    DSA_SHA_256(12, "SHA256withDSA", "DSA"),
    DSA_SHA_384(13, "SHA384withDSA", "DSA"),
    DSA_SHA_512(14, "SHA512withDSA", "DSA"),
    DSA_SHA3_224(15, "SHA3-224withDSA", "DSA"),
    DSA_SHA3_256(16, "SHA3-256withDSA", "DSA"),
    DSA_SHA3_384(17, "SHA3-384withDSA", "DSA"),
    DSA_SHA3_512(18, "SHA3-512withDSA", "DSA"),
    ECDSA(19, "NONEwithECDSA", "EC"),
    ECDSA_SHA_224(20, "SHA224withECDSA", "EC"),
    ECDSA_SHA_256(21, "SHA256withECDSA", "EC"),
    ECDSA_SHA_384(22, "SHA384withECDSA", "EC"),
    ECDSA_SHA_512(23, "SHA512withECDSA", "EC"),
    ECDSA_SHA3_224(24, "SHA3-224withECDSA", "EC"),
    ECDSA_SHA3_256(25, "SHA3-256withECDSA", "EC"),
    ECDSA_SHA3_384(26, "SHA3-384withECDSA", "EC"),
    ECDSA_SHA3_512(27, "SHA3-512withECDSA", "EC");

    private static final Map<Integer, SignatureAlgorithm> idMap = new HashMap<>();

    static {
        for (SignatureAlgorithm algorithm : SignatureAlgorithm.values()) {
            if (algorithm == NONE) {
                continue;
            }

            idMap.put(algorithm.id(), algorithm);
        }
    }

    private final String keyAlgorithmName;
    private final String algorithmName;
    private final int id;

    SignatureAlgorithm(final int id, final String algorithmName, final String keyAlgorithmName) {
        this.id = id;
        this.algorithmName = algorithmName;
        this.keyAlgorithmName = keyAlgorithmName;
    }

    public static SignatureAlgorithm valueOf(final int id) {
        if (!idMap.containsKey(id)) {
            return null;
        }

        return idMap.get(id);
    }

    public String algorithmName() {
        return algorithmName;
    }

    public String keyAlgorithmName() {
        return keyAlgorithmName;
    }

    public int id() {
        return id;
    }

    public Signature instance() {
        try {
            return Signature.getInstance(algorithmName);
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptographyException(ex);
        }
    }

    public Signature instance(final String provider) {
        try {
            return Signature.getInstance(algorithmName, provider);
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            throw new CryptographyException(ex);
        }
    }

    public Signature instance(final Provider provider) {
        try {
            return Signature.getInstance(algorithmName, provider);
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptographyException(ex);
        }
    }
}
