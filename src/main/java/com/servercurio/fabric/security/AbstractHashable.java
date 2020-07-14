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

public abstract class AbstractHashable implements Hashable {

    private Hash hash;
    private HashAlgorithm algorithm;
    private Cryptography cryptography;

    public AbstractHashable() {
        this(HashAlgorithm.SHA_384);
    }

    public AbstractHashable(final HashAlgorithm algorithm) {
        this(algorithm, Cryptography.newDefaultInstance());
    }

    public AbstractHashable(final HashAlgorithm algorithm, final Cryptography cryptography) {
        if (algorithm == null) {
            throw new IllegalArgumentException("algorithm");
        }

        if (cryptography == null) {
            throw new IllegalArgumentException("cryptography");
        }

        this.algorithm = algorithm;
        this.cryptography = cryptography;
    }

    @Override
    public Hash getHash() {
        if (hasHash()) {
            return hash;
        }

        setHash(computeHash(algorithm, cryptography));
        return hash;
    }

    @Override
    public void setHash(final Hash hash) {
        if (this.hash == hash) {
            return;
        }

        this.hash = hash;
    }

    @Override
    public boolean hasHash() {
        return hash != null && !Hash.EMPTY.equals(hash);
    }

    public HashAlgorithm getAlgorithm() {
        return algorithm;
    }

    public Cryptography getCryptography() {
        return cryptography;
    }

    protected abstract Hash computeHash(final HashAlgorithm algorithm, final Cryptography cryptography);
}
