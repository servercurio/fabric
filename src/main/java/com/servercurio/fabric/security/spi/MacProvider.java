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
import com.servercurio.fabric.security.CryptographyException;
import com.servercurio.fabric.security.Hash;
import com.servercurio.fabric.security.MacAlgorithm;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.Key;
import java.util.concurrent.Future;
import javax.crypto.SecretKey;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

/**
 * {@code Fabric Unified Cryptography API} provider definition that encapsulates all of the available message digest
 * functionality. The default algorithm is {@link MacAlgorithm#HMAC_SHA_384} which is the minimum recommended algorithm
 * that is C-NSA compliant. Provider implementations may choose to override the default; however, it is recommended that
 * the default algorithm be a C-NSA compliant algorithm.
 *
 * @author Nathan Klick
 * @see Cryptography
 * @see MacAlgorithm
 */
public interface MacProvider {

    /**
     * Returns the default algorithm. This is the algorithm that will be used when calling the overloaded methods that
     * do not accept the algorithm as a parameter.
     *
     * @return the default algorithm, not null
     */
    default MacAlgorithm getDefaultAlgorithm() {
        return MacAlgorithm.HMAC_SHA_384;
    }

    /**
     * Asynchronously computes the MAC digest of the {@link InputStream} specified by the {@code stream} parameter. This
     * implementation uses the default algorithm provided by the {@link #getDefaultAlgorithm()} method.
     *
     * <p>
     * This implementation will read the input stream from the current position until the end of the stream is reached
     * or no more bytes are available.
     *
     * <p>
     * Care must be taken to ensure the provided {@link InputStream} is not closed before the {@link Future} has been
     * resolved.
     *
     * @param key
     *         the {@link SecretKey} to use when encrypting the computed digest, not null
     * @param stream
     *         the stream to be hashed, not null
     * @return a {@link Future} that when resolved will return the computed {@link Hash}, not null
     * @throws IllegalArgumentException
     *         if the {@code key} or {@code stream} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     * @see #getDefaultAlgorithm()
     */
    default Future<Hash> authenticateAsync(@NotNull final Key key, @NotNull final InputStream stream) {
        return authenticateAsync(getDefaultAlgorithm(), key, stream);
    }

    /**
     * Asynchronously computes the MAC digest of the {@link InputStream} specified by the {@code stream} parameter using
     * the hash algorithm specified by the {@code algorithm} parameter.
     *
     * <p>
     * This implementation will read the input stream from the current position until the end of the stream is reached
     * or no more bytes are available.
     *
     * <p>
     * Care must be taken to ensure the provided {@link InputStream} is not closed before the {@link Future} has been
     * resolved.
     *
     * @param algorithm
     *         the algorithm to use, not null
     * @param key
     *         the {@link SecretKey} to use when encrypting the computed digest, not null
     * @param stream
     *         the stream to be hashed, not null
     * @return a {@link Future} that when resolved will return the computed {@link Hash}, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm}, {@code key}, or {@code stream} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     */
    Future<Hash> authenticateAsync(@NotNull final MacAlgorithm algorithm, @NotNull final Key key,
                                   @NotNull final InputStream stream);

    /**
     * Asynchronously computes the MAC digest of the byte array specified by the {@code data} parameter. This
     * implementation uses the default algorithm provided by the {@link #getDefaultAlgorithm()} method.
     *
     * <p>
     * This implementation will compute the hash of the entire byte array provided by the {@code data} parameter.
     *
     * <p>
     * Care must be taken to ensure the provided byte array is not modified before the {@link Future} has been
     * resolved.
     *
     * @param key
     *         the {@link SecretKey} to use when encrypting the computed digest, not null
     * @param data
     *         the byte array to be hashed, not null
     * @return a {@link Future} that when resolved will return the computed {@link Hash}, not null
     * @throws IllegalArgumentException
     *         if the {@code key} or {@code data} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     * @see #getDefaultAlgorithm()
     */
    default Future<Hash> authenticateAsync(@NotNull final Key key, @NotEmpty final byte[] data) {
        return authenticateAsync(getDefaultAlgorithm(), key, data);
    }

    /**
     * Asynchronously computes the MAC digest of the byte array specified by the {@code data} parameter using the hash
     * algorithm specified by the {@code algorithm} parameter.
     *
     * <p>
     * This implementation will compute the hash of the entire byte array provided by the {@code data} parameter.
     *
     * <p>
     * Care must be taken to ensure the provided byte array is not modified before the {@link Future} has been
     * resolved.
     *
     * @param algorithm
     *         the algorithm to use, not null
     * @param key
     *         the {@link SecretKey} to use when encrypting the computed digest, not null
     * @param data
     *         the byte array to be hashed, not null
     * @return a {@link Future} that when resolved will return the computed {@link Hash}, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm}, {@code key}, or {@code data} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     */
    Future<Hash> authenticateAsync(@NotNull final MacAlgorithm algorithm, @NotNull final Key key,
                                   @NotEmpty final byte[] data);

    /**
     * Asynchronously computes the MAC digest of the {@link Hash} array specified by the {@code hashes} parameter. This
     * implementation uses the default algorithm provided by the {@link #getDefaultAlgorithm()} method.
     *
     * <p>
     * Care must be taken to ensure the provided {@link Hash} array is not modified before the {@link Future} has been
     * resolved.
     *
     * @param key
     *         the {@link SecretKey} to use when encrypting the computed digest, not null
     * @param hashes
     *         the {@link Hash} array to be hashed, not null
     * @return a {@link Future} that when resolved will return the computed {@link Hash}, not null
     * @throws IllegalArgumentException
     *         if the {@code key} or {@code hashes} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     * @see #getDefaultAlgorithm()
     */
    default Future<Hash> authenticateAsync(@NotNull final Key key, @NotEmpty final Hash... hashes) {
        return authenticateAsync(getDefaultAlgorithm(), key, hashes);
    }

    /**
     * Asynchronously computes the MAC digest of the {@link Hash} array specified by the {@code hashes} parameter using
     * the hash algorithm specified by the {@code algorithm} parameter.
     *
     * <p>
     * Care must be taken to ensure the provided byte array is not modified before the {@link Future} has been
     * resolved.
     *
     * @param algorithm
     *         the algorithm to use, not null
     * @param key
     *         the {@link SecretKey} to use when encrypting the computed digest, not null
     * @param hashes
     *         the {@link Hash} array to be hashed, not null
     * @return a {@link Future} that when resolved will return the computed {@link Hash}, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm}, {@code key}, or {@code hashes} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     */
    Future<Hash> authenticateAsync(@NotNull final MacAlgorithm algorithm, @NotNull final Key key,
                                   @NotEmpty final Hash... hashes);

    /**
     * Asynchronously computes the MAC digest of the {@link ByteBuffer} specified by the {@code buffer} parameter. This
     * implementation uses the default algorithm provided by the {@link #getDefaultAlgorithm()} method.
     *
     * <p>
     * This implementation will read the {@link ByteBuffer} from the current position until the end of the buffer is
     * reached.
     *
     * <p>
     * Care must be taken to ensure the provided {@link ByteBuffer} is not modified before the {@link Future} has been
     * resolved.
     *
     * @param key
     *         the {@link SecretKey} to use when encrypting the computed digest, not null
     * @param buffer
     *         the {@link ByteBuffer} to be hashed, not null
     * @return a {@link Future} that when resolved will return the computed {@link Hash}, not null
     * @throws IllegalArgumentException
     *         if the {@code key} or {@code buffer} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     * @see #getDefaultAlgorithm()
     */
    default Future<Hash> authenticateAsync(@NotNull final Key key, @NotNull final ByteBuffer buffer) {
        return authenticateAsync(getDefaultAlgorithm(), key, buffer);
    }

    /**
     * Asynchronously computes the MAC digest of the {@link ByteBuffer} specified by the {@code buffer} parameter using
     * the hash algorithm specified by the {@code algorithm} parameter.
     *
     * <p>
     * This implementation will read the {@link ByteBuffer} from the current position until the end of the buffer is
     * reached.
     *
     * <p>
     * Care must be taken to ensure the provided byte array is not modified before the {@link Future} has been
     * resolved.
     *
     * @param algorithm
     *         the algorithm to use, not null
     * @param key
     *         the {@link SecretKey} to use when encrypting the computed digest, not null
     * @param buffer
     *         the {@link ByteBuffer} to be hashed, not null
     * @return a {@link Future} that when resolved will return the computed {@link Hash}, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm}, {@code key}, or {@code buffer} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     */
    Future<Hash> authenticateAsync(@NotNull final MacAlgorithm algorithm, @NotNull final Key key,
                                   @NotNull final ByteBuffer buffer);

    /**
     * Synchronously computes the MAC digest of the {@link InputStream} specified by the {@code stream} parameter. This
     * implementation uses the default algorithm provided by the {@link #getDefaultAlgorithm()} method.
     *
     * <p>
     * This implementation will read the input stream from the current position until the end of the stream is reached
     * or no more bytes are available.
     *
     * @param key
     *         the {@link SecretKey} to use when encrypting the computed digest, not null
     * @param stream
     *         the stream to be hashed, not null
     * @return the computed hash, not null
     * @throws IllegalArgumentException
     *         if the {@code key} or {@code stream} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     * @see #getDefaultAlgorithm()
     */
    default Hash authenticateSync(@NotNull final Key key, @NotNull final InputStream stream) {
        return authenticateSync(getDefaultAlgorithm(), key, stream);
    }

    /**
     * Synchronously computes the MAC digest of the {@link InputStream} specified by the {@code stream} parameter using
     * the hash algorithm specified by the {@code algorithm} parameter.
     *
     * <p>
     * This implementation will read the input stream from the current position until the end of the stream is reached
     * or no more bytes are available.
     *
     * @param algorithm
     *         the algorithm to use, not null
     * @param key
     *         the {@link SecretKey} to use when encrypting the computed digest, not null
     * @param stream
     *         the stream to be hashed, not null
     * @return the computed hash, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm}, {@code key}, or {@code stream} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     */
    Hash authenticateSync(@NotNull final MacAlgorithm algorithm, @NotNull final Key key,
                          @NotNull final InputStream stream);

    /**
     * Synchronously computes the MAC digest of the byte array specified by the {@code data} parameter. This
     * implementation uses the default algorithm provided by the {@link #getDefaultAlgorithm()} method.
     *
     * <p>
     * This implementation will compute the hash of the entire byte array provided by the {@code data} parameter.
     *
     * @param key
     *         the {@link SecretKey} to use when encrypting the computed digest, not null
     * @param data
     *         the byte array to be hashed, not null
     * @return the computed hash, not null
     * @throws IllegalArgumentException
     *         if the {@code key} or {@code data} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     * @see #getDefaultAlgorithm()
     */
    default Hash authenticateSync(@NotNull final Key key, @NotEmpty final byte[] data) {
        return authenticateSync(getDefaultAlgorithm(), key, data);
    }

    /**
     * Synchronously computes the MAC digest of the byte array specified by the {@code data} parameter using the hash
     * algorithm specified by the {@code algorithm} parameter.
     *
     * <p>
     * This implementation will compute the hash of the entire byte array provided by the {@code data} parameter.
     *
     * @param algorithm
     *         the algorithm to use, not null
     * @param key
     *         the {@link SecretKey} to use when encrypting the computed digest, not null
     * @param data
     *         the byte array to be hashed, not null
     * @return the computed hash, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm}, {@code key}, or {@code data} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     */
    Hash authenticateSync(@NotNull final MacAlgorithm algorithm, @NotNull final Key key, @NotEmpty final byte[] data);

    /**
     * Synchronously computes the MAC digest of the {@link Hash} array specified by the {@code hashes} parameter. This
     * implementation uses the default algorithm provided by the {@link #getDefaultAlgorithm()} method.
     *
     * @param key
     *         the {@link SecretKey} to use when encrypting the computed digest, not null
     * @param hashes
     *         the {@link Hash} array to be hashed, not null
     * @return the computed hash, not null
     * @throws IllegalArgumentException
     *         if the {@code key} or {@code hashes} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     * @see #getDefaultAlgorithm()
     */
    default Hash authenticateSync(@NotNull final Key key, @NotEmpty final Hash... hashes) {
        return authenticateSync(getDefaultAlgorithm(), key, hashes);
    }

    /**
     * Synchronously computes the MAC digest of the {@link Hash} array specified by the {@code hashes} parameter using
     * the hash algorithm specified by the {@code algorithm} parameter.
     *
     * @param algorithm
     *         the algorithm to use, not null
     * @param key
     *         the {@link SecretKey} to use when encrypting the computed digest, not null
     * @param hashes
     *         the {@link Hash} array to be hashed, not null
     * @return the computed hash, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm}, {@code key}, or {@code hashes} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     */
    Hash authenticateSync(@NotNull final MacAlgorithm algorithm, @NotNull final Key key,
                          @NotEmpty final Hash... hashes);

    /**
     * Synchronously computes the MAC digest of the {@link ByteBuffer} specified by the {@code buffer} parameter. This
     * implementation uses the default algorithm provided by the {@link #getDefaultAlgorithm()} method.
     *
     * <p>
     * This implementation will read the {@link ByteBuffer} from the current position until the end of the buffer is
     * reached.
     *
     * @param key
     *         the {@link SecretKey} to use when encrypting the computed digest, not null
     * @param buffer
     *         the {@link ByteBuffer} to be hashed, not null
     * @return the computed hash, not null
     * @throws IllegalArgumentException
     *         if the {@code key} or {@code buffer} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     * @see #getDefaultAlgorithm()
     */
    default Hash authenticateSync(@NotNull final Key key, @NotNull final ByteBuffer buffer) {
        return authenticateSync(getDefaultAlgorithm(), key, buffer);
    }

    /**
     * Synchronously computes the MAC digest of the {@link ByteBuffer} specified by the {@code buffer} parameter using
     * the hash algorithm specified by the {@code algorithm} parameter.
     *
     * <p>
     * This implementation will read the {@link ByteBuffer} from the current position until the end of the buffer is
     * reached.
     *
     * @param algorithm
     *         the algorithm to use, not null
     * @param key
     *         the {@link SecretKey} to use when encrypting the computed digest, not null
     * @param buffer
     *         the {@link ByteBuffer} to be hashed, not null
     * @return the computed hash, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm}, {@code key}, or {@code buffer} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     */
    Hash authenticateSync(@NotNull final MacAlgorithm algorithm, @NotNull final Key key,
                          @NotNull final ByteBuffer buffer);
}
