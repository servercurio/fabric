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

package com.servercurio.fabric.core.collections.spi;

import com.servercurio.fabric.core.collections.MerkleMap;
import com.servercurio.fabric.core.collections.MerkleMapException;
import com.servercurio.fabric.core.collections.MerkleMapNode;
import com.servercurio.fabric.core.collections.MerkleTree;
import com.servercurio.fabric.core.security.HashAlgorithm;
import com.servercurio.fabric.core.serialization.ObjectId;
import com.servercurio.fabric.core.serialization.ObjectSerializer;
import com.servercurio.fabric.core.serialization.SerializationAware;
import com.servercurio.fabric.core.serialization.Version;
import com.servercurio.fabric.core.serialization.spi.AbstractSerializationProvider;
import com.servercurio.fabric.core.serialization.spi.SerializationProvider;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class MerkleMapSerializationProvider extends AbstractSerializationProvider {

    public MerkleMapSerializationProvider() {
        // Method is currently empty because no initialization is required
    }

    @Override
    protected void handleObjectRegistration() {
        registerObject(MerkleMap.OBJECT_ID, MerkleMap.class, MerkleMap.VERSIONS);
        registerObject(MerkleMapNode.OBJECT_ID, MerkleMapNode.class, MerkleMapNode.VERSIONS);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T extends SerializationAware> T deserialize(final ObjectSerializer objectSerializer,
                                                        final DataInputStream inStream, final ObjectId objectId,
                                                        final Version version) throws IOException {
        if (MerkleMap.OBJECT_ID.equals(objectId) && MerkleMap.VERSIONS.contains(version)) {
            final int algorithmId = inStream.readInt();
            final HashAlgorithm algorithm = HashAlgorithm.valueOf(algorithmId);

            final MerkleMap<SerializationAware, SerializationAware> merkleMap = new MerkleMap<>(algorithm);
            final MerkleTree<MerkleMapNode<?, ?>> tree = objectSerializer.deserialize(inStream);

            for (MerkleMapNode<?, ?> node : tree) {
                merkleMap.put(node.getKey(), node.getValue());
            }

            if (!tree.getHash().equals(merkleMap.getHash())) {
                throw new MerkleMapException(String.format(
                        "Deserialized MerkleMap hash does not match serialized hash " +
                        "[ originalHash = '%s', computedHash = '%s' ]",
                        tree.getHash(), merkleMap.getHash()));
            }

            return (T) merkleMap;
        } else if (MerkleMapNode.OBJECT_ID.equals(objectId) && MerkleMapNode.VERSIONS.contains(version)) {
            final int algorithmId = inStream.readInt();
            final HashAlgorithm algorithm = HashAlgorithm.valueOf(algorithmId);

            final SerializationAware key = objectSerializer.deserialize(inStream);
            final SerializationAware value = objectSerializer.deserialize(inStream);

            return (T) new MerkleMapNode<>(key, value, algorithm);
        }

        return null;
    }

    @Override
    public <T extends SerializationAware> void serialize(final ObjectSerializer objectSerializer,
                                                         final DataOutputStream outStream,
                                                         final T object) throws IOException {

        if (object instanceof MerkleMap) {
            final MerkleMap<?, ?> merkleMap = (MerkleMap<?, ?>) object;
            outStream.writeInt(merkleMap.getAlgorithm().id());
            objectSerializer.serialize(outStream, merkleMap.getMerkleTree());
        } else if (object instanceof MerkleMapNode) {
            final MerkleMapNode<?, ?> mapNode = (MerkleMapNode<?, ?>) object;
            outStream.writeInt(mapNode.getAlgorithm().id());
            objectSerializer.serialize(outStream, mapNode.getKey());
            objectSerializer.serialize(outStream, mapNode.getValue());
        }
    }
}
