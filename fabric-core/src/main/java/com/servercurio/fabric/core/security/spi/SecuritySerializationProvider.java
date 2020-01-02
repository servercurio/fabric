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

package com.servercurio.fabric.core.security.spi;

import com.servercurio.fabric.core.io.BadIOException;
import com.servercurio.fabric.core.security.Hash;
import com.servercurio.fabric.core.security.HashAlgorithm;
import com.servercurio.fabric.core.serialization.*;
import com.servercurio.fabric.core.serialization.spi.SerializationProvider;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public final class SecuritySerializationProvider implements SerializationProvider {

    public SecuritySerializationProvider() {
        // Method is currently empty because no initialization is required
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T extends SerializationAware> T deserialize(final ObjectSerializer objectSerializer,
                                                        final DataInputStream inStream, final ObjectId objectId,
                                                        final Version version) throws IOException {

        if (Hash.OBJECT_ID.equals(objectId) && Hash.VERSIONS.contains(version)) {
            final int hashType = inStream.readInt();
            final HashAlgorithm algorithm = HashAlgorithm.valueOf(hashType);

            if (algorithm == null) {
                throw new BadIOException();
            }

            final byte[] hashValue = new byte[algorithm.bytes()];

            if (algorithm != HashAlgorithm.NONE) {
                inStream.readFully(hashValue);
            }

            return (T) new Hash(algorithm, hashValue, false);
        }

        return null;
    }

    @Override
    public <T extends SerializationAware> boolean isSupported(final T object) {
        return (object instanceof Hash);
    }

    @Override
    public boolean isSupported(final ObjectId objectId, final Version version) {
        return Hash.OBJECT_ID.equals(objectId) && Hash.VERSIONS.contains(version);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T extends SerializationAware> T newInstance(final ObjectId objectId, final Version version) {
        if (Hash.OBJECT_ID.equals(objectId) && Hash.VERSIONS.last().equals(version)) {
            return (T) new Hash();
        }

        return null;
    }

    @Override
    public <T extends SerializationAware> void serialize(final ObjectSerializer objectSerializer,
                                                         final DataOutputStream outStream,
                                                         final T object) throws IOException {

        if (Hash.OBJECT_ID.equals(object.getObjectId()) && Hash.VERSIONS.contains(object.getVersion())) {
            final Hash hash = (Hash) object;
            outStream.writeInt(hash.getAlgorithm().id());

            if (hash.getAlgorithm() != HashAlgorithm.NONE) {
                outStream.write(hash.getValue());
            }
        } else {
            throw new ObjectNotSerializableException(object.getClass().getName());
        }

    }

}
