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

import java.util.HashMap;
import java.util.Map;

public enum CipherPadding {
    NONE(0, "NoPadding"),
    ISO10126(1, "ISO10126Padding"),
    PKCS1(2, "PKCS1Padding"),
    PKCS5(3, "PKCS5Padding"),
    SSL3(4, "SSL3Padding");

    private static final Map<Integer, CipherPadding> idMap = new HashMap<>();

    static {
        for (CipherPadding algorithm : CipherPadding.values()) {
            if (algorithm == NONE) {
                continue;
            }

            idMap.put(algorithm.id(), algorithm);
        }
    }

    private final String paddingName;
    private final int id;

    CipherPadding(final int id, final String paddingName) {
        this.id = id;
        this.paddingName = paddingName;
    }

    public static CipherPadding valueOf(final int id) {
        if (!idMap.containsKey(id)) {
            return null;
        }

        return idMap.get(id);
    }

    public String paddingName() {
        return paddingName;
    }

    public int id() {
        return id;
    }
}
