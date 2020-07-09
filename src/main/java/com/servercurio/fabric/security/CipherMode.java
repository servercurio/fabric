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

public enum CipherMode {
    NONE(0, "NONE"),
    CBC(1, "CBC"),
    CCM(2, "CCM"),
    CFB(3, "CFB"),
    CFB8(4, "CFB8"),
    CTR(5, "CTR"),
    CTS(6, "CTS"),
    ECB(7, "ECB"),
    GCM(8, "GCM"),
    OFB(9, "OFB"),
    OFB8(10, "OFB8"),
    PCBC(11, "PCBC");

    private static final Map<Integer, CipherMode> idMap = new HashMap<>();

    static {
        for (CipherMode algorithm : CipherMode.values()) {
            if (algorithm == NONE) {
                continue;
            }

            idMap.put(algorithm.id(), algorithm);
        }
    }

    private final String modeName;
    private final int id;

    CipherMode(final int id, final String modeName) {
        this.id = id;
        this.modeName = modeName;
    }

    public static CipherMode valueOf(final int id) {
        if (!idMap.containsKey(id)) {
            return null;
        }

        return idMap.get(id);
    }

    public String modeName() {
        return modeName;
    }


    public int id() {
        return id;
    }
}
