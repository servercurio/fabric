/*
 * Copyright 2019 Server Curio
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

package com.servercurio.fabric.core.security;

import com.servercurio.fabric.core.security.impl.DefaultCryptographyImpl;
import com.servercurio.fabric.core.serialization.SerializationAware;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;

public interface Cryptography {

    static Cryptography getDefaultInstance() {
        return DefaultCryptographyImpl.getInstance();
    }

    Hash digestSync(final InputStream stream);

    Hash digestSync(final HashAlgorithm algorithm, final InputStream stream);

    Hash digestSync(final byte[] data) throws NoSuchAlgorithmException;

    Hash digestSync(final HashAlgorithm algorithm, final byte[] data);

    Hash digestSync(final Hash leftHash, final Hash rightHash);

    Hash digestSync(final HashAlgorithm algorithm, final Hash leftHash, final Hash rightHash);

    Hash digestSync(final ByteBuffer buffer) throws NoSuchAlgorithmException;

    Hash digestSync(final HashAlgorithm algorithm, final ByteBuffer buffer);

    Hash digestSync(final SerializationAware serialObject);

    Hash digestSync(final HashAlgorithm algorithm, final SerializationAware serialObject);

}
