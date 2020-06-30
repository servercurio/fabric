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

import java.nio.ByteBuffer;

public class MockHash extends Hash {

    private HashAlgorithm overrideAlgorithm;

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

    public void setOverrideAlgorithm(final HashAlgorithm overrideAlgorithm) {
        this.overrideAlgorithm = overrideAlgorithm;
    }

    public byte[] toByteArray() {
        final ByteBuffer buffer = ByteBuffer.allocate(52);

        buffer.putInt(getAlgorithm().id()).put(getValue());

        return buffer.array();
    }

    @Override
    public HashAlgorithm getAlgorithm() {
        return (overrideAlgorithm != null) ? overrideAlgorithm : super.getAlgorithm();
    }
}
