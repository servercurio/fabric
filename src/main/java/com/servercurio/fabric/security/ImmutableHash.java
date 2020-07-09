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

import java.util.Arrays;

/**
 * @author Nathan Klick
 * @see Hash
 * @since 1.0
 */
public class ImmutableHash extends Hash {

    public ImmutableHash(final Hash other) {
        super(other);
    }

    /**
     * {@inheritDoc}
     *
     * @param algorithm
     *         {@inheritDoc}
     * @throws UnsupportedOperationException
     *         always because this method is not supported on immutable instances
     */
    @Override
    public void setAlgorithm(final HashAlgorithm algorithm) {
       throw new UnsupportedOperationException();
    }

    /**
     * Returns a copy of the underlying byte array containing the hash value.
     *
     * @return a copy of the underlying byte array, not null
     * @see HashAlgorithm
     * @see Hash#getAlgorithm()
     */
    @Override
    public byte[] getValue() {
        final byte[] value = super.getValue();

        return Arrays.copyOf(value, value.length);
    }

    /**
     * {@inheritDoc}
     *
     * @param value
     *         {@inheritDoc}
     * @throws UnsupportedOperationException
     *         always because this method is not supported on immutable instances
     */
    @Override
    public void setValue(final byte[] value) {
        throw new UnsupportedOperationException();
    }

}
