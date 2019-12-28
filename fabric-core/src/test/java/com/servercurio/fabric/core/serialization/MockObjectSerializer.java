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

package com.servercurio.fabric.core.serialization;

import com.servercurio.fabric.core.serialization.spi.SerializationProvider;

import java.io.DataInputStream;
import java.io.IOException;

public class MockObjectSerializer extends ObjectSerializer {

    public MockObjectSerializer() {
        super();
    }

    public boolean checkProvider(final ObjectId oid, final Version version) throws UnknownObjectIdentifierException {
        return this.provider(oid, version) != null;
    }

    public <T extends SerializationAware> T newInstance(final ObjectId oid, final Version version) throws UnknownObjectIdentifierException {
        final SerializationProvider provider = provider(oid, version);
        return provider.newInstance(oid, version);
    }

    public <T extends SerializationAware> T newInstance(final SerializationProvider provider, final ObjectId oid, final Version version) {
        return provider.newInstance(oid, version);
    }

    public <T extends SerializationAware> T deserialize(final SerializationProvider provider, final DataInputStream inStream) throws IOException {

        if (inStream == null) {
            throw new IllegalArgumentException("inStream");
        }

        final int namespace = inStream.readInt();
        final int id = inStream.readInt();

        final int major = inStream.readInt();
        final int minor = inStream.readInt();
        final int revision = inStream.readInt();

        final ObjectId objectId = new ObjectId(namespace, id);
        final Version version = new Version(major, minor, revision);

        return provider.deserialize(this, inStream, objectId, version);

    }
}
