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

package com.servercurio.fabric.core.serialization.spi;

import com.servercurio.fabric.core.security.AbstractHashable;
import com.servercurio.fabric.core.security.HashAlgorithm;
import com.servercurio.fabric.core.serialization.*;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class PrimitiveSerializationProvider extends AbstractSerializationProvider {

    public PrimitiveSerializationProvider() {
        // Method is currently empty because no initialization is required
    }

    @Override
    protected void handleObjectRegistration() {
        registerObject(SerializableString.OBJECT_ID, SerializableString.class, SerializableString.VERSIONS);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T extends SerializationAware> T deserialize(final ObjectSerializer objectSerializer,
                                                        final DataInputStream inStream, final ObjectId objectId,
                                                        final Version version) throws IOException {
        final boolean hashable = inStream.readBoolean();
        HashAlgorithm algorithm = HashAlgorithm.SHA_384;

        if (hashable) {
            final int algorithmId = inStream.readInt();
            algorithm = HashAlgorithm.valueOf(algorithmId);
        }

        final int bufferSize = inStream.readInt();
        final byte[] buffer = new byte[bufferSize];

        inStream.readFully(buffer);

        SerializationAware object = null;

        if (SerializableString.OBJECT_ID.equals(objectId) && SerializableString.VERSIONS.contains(version)) {
            object = new SerializableString(algorithm);
        }

        if (object != null) {
            ((ByteConvertible) object).fromBytes(buffer);
        }

        return (T) object;
    }

    @Override
    public <T extends SerializationAware> void serialize(final ObjectSerializer objectSerializer,
                                                         final DataOutputStream outStream,
                                                         final T object) throws IOException {
        if (object instanceof ByteConvertible) {
            final ByteConvertible convertible = (ByteConvertible) object;
            final byte[] buffer = convertible.toBytes();

            if (object instanceof AbstractHashable) {
                final AbstractHashable hashable = (AbstractHashable) object;

                outStream.writeBoolean(true);
                outStream.writeInt(hashable.getAlgorithm().id());
            } else {
                outStream.writeBoolean(false);
            }

            outStream.writeInt(buffer.length);
            outStream.write(buffer);
        }
    }
}
