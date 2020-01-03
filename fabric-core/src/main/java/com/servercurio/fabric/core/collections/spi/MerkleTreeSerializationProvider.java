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

import com.servercurio.fabric.core.collections.MerkleTree;
import com.servercurio.fabric.core.collections.MerkleTreeException;
import com.servercurio.fabric.core.security.Hash;
import com.servercurio.fabric.core.security.HashAlgorithm;
import com.servercurio.fabric.core.serialization.ObjectId;
import com.servercurio.fabric.core.serialization.ObjectSerializer;
import com.servercurio.fabric.core.serialization.SerializationAware;
import com.servercurio.fabric.core.serialization.Version;
import com.servercurio.fabric.core.serialization.spi.SerializationProvider;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class MerkleTreeSerializationProvider implements SerializationProvider {

    public MerkleTreeSerializationProvider() {
        // Method is currently empty because no initialization is required
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T extends SerializationAware> T deserialize(final ObjectSerializer objectSerializer,
                                                        final DataInputStream inStream, final ObjectId objectId,
                                                        final Version version) throws IOException {
        if (MerkleTree.OBJECT_ID.equals(objectId) && MerkleTree.VERSIONS.contains(version)) {
            final int treeSize = inStream.readInt();
            final int algorithmId = inStream.readInt();
            final HashAlgorithm algorithm = HashAlgorithm.valueOf(algorithmId);
            final Hash hash = objectSerializer.deserialize(inStream);

            final MerkleTree<SerializationAware> tree = new MerkleTree<>(algorithm);

            for (int i = 0; i < treeSize; i++) {
                final SerializationAware value = objectSerializer.deserialize(inStream);
                tree.add(value);
            }

            if (!hash.equals(tree.getHash())) {
                throw new MerkleTreeException(String.format(
                        "Deserialized MerkleTree hash does not match serialized hash " +
                        "[ originalHash = '%s', computedHash = '%s' ]",
                        hash, tree.getHash()));
            }

            return (T) tree;
        }

        return null;
    }

    @Override
    public <T extends SerializationAware> boolean isSupported(final T object) {
        return (object instanceof MerkleTree);
    }

    @Override
    public boolean isSupported(final ObjectId objectId, final Version version) {
        return (MerkleTree.OBJECT_ID.equals(objectId) && MerkleTree.VERSIONS.contains(version));
    }

    @Override
    public <T extends SerializationAware> T newInstance(final ObjectId objectId, final Version version) {
        throw new UnsupportedOperationException();
    }

    @Override
    public <T extends SerializationAware> void serialize(final ObjectSerializer objectSerializer,
                                                         final DataOutputStream outStream,
                                                         final T object) throws IOException {
        if (object instanceof MerkleTree) {
            final MerkleTree<?> tree = (MerkleTree<?>) object;

            outStream.writeInt(tree.size());
            outStream.writeInt(tree.getHashAlgorithm().id());
            objectSerializer.serialize(outStream, tree.getHash());

            for (final SerializationAware value : tree) {
                objectSerializer.serialize(outStream, value);
            }
        }
    }
}