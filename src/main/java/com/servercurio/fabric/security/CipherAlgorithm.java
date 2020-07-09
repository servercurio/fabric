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

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

public enum CipherAlgorithm {
    NONE(0, "NONE"),
    AES_128(1, "AES_128"),
    AES_192(2, "AES_192"),
    AES_256(3, "AES_256");

    private static final Map<Integer, CipherAlgorithm> idMap = new HashMap<>();

    static {
        for (CipherAlgorithm algorithm : CipherAlgorithm.values()) {
            if (algorithm == NONE) {
                continue;
            }

            idMap.put(algorithm.id(), algorithm);
        }
    }

    private final String algorithmName;
    private final int id;

    CipherAlgorithm(final int id, final String algorithmName) {
        this.id = id;
        this.algorithmName = algorithmName;
    }

    public static CipherAlgorithm valueOf(final int id) {
        if (!idMap.containsKey(id)) {
            return null;
        }

        return idMap.get(id);
    }

    public String algorithmName() {
        return algorithmName;
    }

    public int id() {
        return id;
    }

}
