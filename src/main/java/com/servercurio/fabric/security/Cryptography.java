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

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;

public interface Cryptography extends AutoCloseable {

    static Cryptography getDefaultInstance() {
        return DefaultCryptographyImpl.getInstance();
    }

    static Cryptography newDefaultInstance() {
        return DefaultCryptographyImpl.newInstance();
    }

    Hash digestSync(final InputStream stream);

    Hash digestSync(final InputStream stream, final HashAlgorithm algorithm);

    Hash digestSync(final byte[] data);

    Hash digestSync(final byte[] data, final HashAlgorithm algorithm);

    Hash digestSync(final Hash leftHash, final Hash rightHash);

    Hash digestSync(final Hash leftHash, final Hash rightHash, final HashAlgorithm algorithm);

    Hash digestSync(final ByteBuffer buffer) throws NoSuchAlgorithmException;

    Hash digestSync(final ByteBuffer buffer, final HashAlgorithm algorithm);

}
