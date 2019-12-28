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

import com.servercurio.fabric.core.serialization.ObjectId;
import com.servercurio.fabric.core.serialization.Version;

import java.nio.ByteBuffer;

public class MockHash extends Hash {

    private HashAlgorithm overrideAlgorithm;
    private Version overrideVersion;
    private ObjectId overrideObjectId;

    public MockHash() {
        super();
    }

    public MockHash(final HashAlgorithm algorithm, final byte[] value) {
        super(algorithm, value);
    }

    public MockHash(final HashAlgorithm algorithm, final byte[] value, final boolean copyValue) {
        super(algorithm, value, copyValue);
    }

    public MockHash(final Hash other) {
        super(other);
    }



    @Override
    public Version getVersion() {
        return (overrideVersion != null) ? overrideVersion : super.getVersion();
    }

    @Override
    public HashAlgorithm getAlgorithm() {
        return (overrideAlgorithm != null) ? overrideAlgorithm : super.getAlgorithm();
    }

    @Override
    public ObjectId getObjectId() {
        return (overrideObjectId != null) ? overrideObjectId : super.getObjectId();
    }

    public void setOverrideAlgorithm(final HashAlgorithm overrideAlgorithm) {
        this.overrideAlgorithm = overrideAlgorithm;
    }

    public void setOverrideVersion(final Version overrideVersion) {
        this.overrideVersion = overrideVersion;
    }

    public void setOverrideObjectId(final ObjectId overrideObjectId) {
        this.overrideObjectId = overrideObjectId;
    }

    public byte[] toByteArray() {
        final ByteBuffer buffer = ByteBuffer.allocate(72);
        final ObjectId hashOid = getObjectId();
        final Version hashVersion = getVersion();

        buffer.putInt(hashOid.getNamespace()).putInt(hashOid.getIdentifier()).putInt(hashVersion.getMajor())
                .putInt(hashVersion.getMinor()).putInt(hashVersion.getRevision())
                .putInt(getAlgorithm().id()).put(getValue());

        return buffer.array();
    }
}
