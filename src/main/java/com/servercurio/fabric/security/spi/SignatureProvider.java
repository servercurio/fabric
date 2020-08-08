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

package com.servercurio.fabric.security.spi;

import com.servercurio.fabric.security.Cryptography;
import com.servercurio.fabric.security.Hash;
import com.servercurio.fabric.security.Seal;
import com.servercurio.fabric.security.SignatureAlgorithm;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.concurrent.Future;

/**
 * {@code Fabric Unified Cryptography API} provider definition that encapsulates all of the available message digest
 * functionality. The default algorithm is {@link SignatureAlgorithm#RSA_SHA_384} which is the minimum recommended
 * algorithm that is C-NSA compliant. Provider implementations may choose to override the default; however, it is
 * recommended that the default algorithm be a C-NSA compliant algorithm.
 *
 * @author Nathan Klick
 * @see Cryptography
 * @see SignatureAlgorithm
 */
public interface SignatureProvider {

    /**
     * Returns the default algorithm. This is the algorithm that will be used when calling the overloaded methods that
     * do not accept the algorithm as a parameter.
     *
     * @return the default algorithm, not null
     */
    default SignatureAlgorithm getDefaultAlgorithm() {
        return SignatureAlgorithm.RSA_SHA_384;
    }

    /**
     * @param key
     * @param stream
     * @return
     */
    default Future<Seal> signAsync(final PrivateKey key, final InputStream stream) {
        return signAsync(getDefaultAlgorithm(), key, stream);
    }

    /**
     * @param algorithm
     * @param key
     * @param stream
     * @return
     */
    Future<Seal> signAsync(final SignatureAlgorithm algorithm, final PrivateKey key, final InputStream stream);

    /**
     * @param key
     * @param data
     * @return
     */
    default Future<Seal> signAsync(final PrivateKey key, final byte[] data) {
        return signAsync(getDefaultAlgorithm(), key, data);
    }

    /**
     * @param algorithm
     * @param key
     * @param data
     * @return
     */
    Future<Seal> signAsync(final SignatureAlgorithm algorithm, final PrivateKey key, final byte[] data);

    /**
     * @param key
     * @param hashes
     * @return
     */
    default Future<Seal> signAsync(final PrivateKey key, final Hash... hashes) {
        return signAsync(getDefaultAlgorithm(), key, hashes);
    }

    /**
     * @param algorithm
     * @param key
     * @param hashes
     * @return
     */
    Future<Seal> signAsync(final SignatureAlgorithm algorithm, final PrivateKey key, final Hash... hashes);

    /**
     * @param key
     * @param buffer
     * @return
     */
    default Future<Seal> signAsync(final PrivateKey key, final ByteBuffer buffer) {
        return signAsync(getDefaultAlgorithm(), key, buffer);
    }

    /**
     * @param algorithm
     * @param key
     * @param buffer
     * @return
     */
    Future<Seal> signAsync(final SignatureAlgorithm algorithm, final PrivateKey key, final ByteBuffer buffer);

    /**
     * @param key
     * @param stream
     * @return
     */
    default Seal signSync(final PrivateKey key, final InputStream stream) {
        return signSync(getDefaultAlgorithm(), key, stream);
    }

    /**
     * @param algorithm
     * @param key
     * @param stream
     * @return
     */
    Seal signSync(final SignatureAlgorithm algorithm, final PrivateKey key, final InputStream stream);

    /**
     * @param key
     * @param data
     * @return
     */
    default Seal signSync(final PrivateKey key, final byte[] data) {
        return signSync(getDefaultAlgorithm(), key, data);
    }

    /**
     * @param algorithm
     * @param key
     * @param data
     * @return
     */
    Seal signSync(final SignatureAlgorithm algorithm, final PrivateKey key, final byte[] data);

    /**
     * @param key
     * @param hashes
     * @return
     */
    default Seal signSync(final PrivateKey key, final Hash... hashes) {
        return signSync(getDefaultAlgorithm(), key, hashes);
    }

    /**
     * @param algorithm
     * @param key
     * @param hashes
     * @return
     */
    Seal signSync(final SignatureAlgorithm algorithm, final PrivateKey key, final Hash... hashes);

    /**
     * @param key
     * @param buffer
     * @return
     */
    default Seal signSync(final PrivateKey key, final ByteBuffer buffer) {
        return signSync(getDefaultAlgorithm(), key, buffer);
    }

    /**
     * @param algorithm
     * @param key
     * @param buffer
     * @return
     */
    Seal signSync(final SignatureAlgorithm algorithm, final PrivateKey key, final ByteBuffer buffer);

    /**
     * @param seal
     * @param key
     * @param stream
     * @return
     */
    Future<Boolean> verifyAsync(final Seal seal, final PublicKey key, final InputStream stream);

    /**
     * @param seal
     * @param key
     * @param data
     * @return
     */
    Future<Boolean> verifyAsync(final Seal seal, final PublicKey key, final byte[] data);

    /**
     * @param seal
     * @param key
     * @param hashes
     * @return
     */
    Future<Boolean> verifyAsync(final Seal seal, final PublicKey key, final Hash... hashes);

    /**
     * @param seal
     * @param key
     * @param buffer
     * @return
     */
    Future<Boolean> verifyAsync(final Seal seal, final PublicKey key, final ByteBuffer buffer);

    /**
     * @param seal
     * @param key
     * @param stream
     * @return
     */
    boolean verifySync(final Seal seal, final PublicKey key, final InputStream stream);

    /**
     * @param seal
     * @param key
     * @param data
     * @return
     */
    boolean verifySync(final Seal seal, final PublicKey key, final byte[] data);

    /**
     * @param seal
     * @param key
     * @param hashes
     * @return
     */
    boolean verifySync(final Seal seal, final PublicKey key, final Hash... hashes);

    /**
     * @param seal
     * @param key
     * @param buffer
     * @return
     */
    boolean verifySync(final Seal seal, final PublicKey key, final ByteBuffer buffer);
}
