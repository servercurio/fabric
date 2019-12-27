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

import com.servercurio.fabric.core.serialization.ObjectId;
import com.servercurio.fabric.core.serialization.ObjectSerializer;
import com.servercurio.fabric.core.serialization.SerializationAware;
import com.servercurio.fabric.core.serialization.Version;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public interface SerializationProvider {

    <T extends SerializationAware> T deserialize(final ObjectSerializer objectSerializer, final DataInputStream inStream, final ObjectId objectId, final Version version) throws IOException;

    <T extends SerializationAware> boolean isSupported(final T object);

    boolean isSupported(final ObjectId objectId, final Version version);

    <T extends SerializationAware> T newInstance(final ObjectId objectId, final Version version);

    <T extends SerializationAware> void serialize(final ObjectSerializer objectSerializer, final DataOutputStream outStream, final T object) throws IOException;

}
