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

import com.servercurio.fabric.core.security.Cryptography;
import com.servercurio.fabric.core.security.Hash;
import com.servercurio.fabric.core.security.Hashable;

import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.SortedSet;
import java.util.TreeSet;

public class MockSerializable implements SerializationAware, Hashable {

    public static final ObjectId OBJECT_ID = new ObjectId(0, 1);

    public static SortedSet<Version> VERSIONS;

    private byte[] integerValue;
    private Hash hash;

    static {
        final TreeSet<Version> versionSet = new TreeSet<>();
        versionSet.add(new Version(1, 0, 0));

        VERSIONS = Collections.unmodifiableSortedSet(versionSet);
    }

    public MockSerializable() {
        this(0);
    }

    public MockSerializable(final int integerValue) {
        this.integerValue = ByteBuffer.allocate(Integer.BYTES).putInt(integerValue).array();
    }

    public int getIntegerValue() {
        return ByteBuffer.wrap(integerValue).getInt();
    }

    @Override
    public ObjectId getObjectId() {
        return OBJECT_ID;
    }

    @Override
    public SortedSet<Version> getVersionHistory() {
        return VERSIONS;
    }

    @Override
    public Version getVersion() {
        return VERSIONS.last();
    }

    @Override
    public Hash getHash() {
        if (hash != null) {
            return hash;
        }

        hash = Cryptography.getDefaultInstance().digestSync(integerValue);
        return hash;
    }

    @Override
    public void setHash(final Hash hash) {
        this.hash = hash;
    }

    @Override
    public boolean hasHash() {
        return hash != null;
    }
}
