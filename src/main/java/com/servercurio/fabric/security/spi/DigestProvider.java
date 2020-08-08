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
import com.servercurio.fabric.security.HashAlgorithm;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.concurrent.Future;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

/**
 * Cryptography Provider definition that encapsulates all of the available message digest functionality. The default
 * algorithm is {@link HashAlgorithm#SHA_384} which is the minimum recommended algorithm that is C-NSA compliant.
 * Provider implementations may choose to override the default; however, it is recommended that the default algorithm be
 * a C-NSA compliant algorithm.
 *
 * @author Nathan Klick
 * @see Cryptography
 * @see HashAlgorithm
 */
public interface DigestProvider {

    /**
     * Returns the default algorithm. This is the algorithm that will be used when calling the overloaded methods that
     * do not accept the algorithm as a parameter.
     *
     * @return the default algorithm, not null
     */
    default HashAlgorithm getDefaultAlgorithm() {
        return HashAlgorithm.SHA_384;
    }

    /**
     * Asynchronously computes the digest of the {@link InputStream} specified by the {@code stream} parameter. This
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
     * @param stream
     *         the stream to be hashed, not null
     * @return a {@link Future} that when resolved will return the computed {@link Hash}, not null
     * @throws IllegalArgumentException
     *         if the {@code stream} parameter is null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     * @see #getDefaultAlgorithm()
     */
    default Future<Hash> digestAsync(@NotNull final InputStream stream) {
        return digestAsync(getDefaultAlgorithm(), stream);
    }

    /**
     * Asynchronously computes the digest of the {@link InputStream} specified by the {@code stream} parameter using the
     * hash algorithm specified by the {@code algorithm} parameter.
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
     * @param stream
     *         the stream to be hashed, not null
     * @return a {@link Future} that when resolved will return the computed {@link Hash}, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm} or the {@code stream} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     */
    Future<Hash> digestAsync(@NotNull final HashAlgorithm algorithm, @NotNull final InputStream stream);

    /**
     * Asynchronously computes the digest of the byte array specified by the {@code data} parameter. This implementation
     * uses the default algorithm provided by the {@link #getDefaultAlgorithm()} method.
     *
     * <p>
     * This implementation will compute the hash of the entire byte array provided by the {@code data} parameter.
     *
     * <p>
     * Care must be taken to ensure the provided byte array is not modified before the {@link Future} has been
     * resolved.
     *
     * @param data
     *         the byte array to be hashed, not null
     * @return a {@link Future} that when resolved will return the computed {@link Hash}, not null
     * @throws IllegalArgumentException
     *         if the {@code data} parameter is null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     * @see #getDefaultAlgorithm()
     */
    default Future<Hash> digestAsync(@NotNull final byte[] data) {
        return digestAsync(getDefaultAlgorithm(), data);
    }

    /**
     * Asynchronously computes the digest of the byte array specified by the {@code data} parameter using the hash
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
     * @param data
     *         the byte array to be hashed, not null
     * @return a {@link Future} that when resolved will return the computed {@link Hash}, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm} or the {@code data} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     */
    Future<Hash> digestAsync(@NotNull final HashAlgorithm algorithm, @NotNull final byte[] data);

    /**
     * Asynchronously computes the digest of the {@link Hash} array specified by the {@code hashes} parameter. This
     * implementation uses the default algorithm provided by the {@link #getDefaultAlgorithm()} method.
     *
     * <p>
     * Care must be taken to ensure the provided {@link Hash} array is not modified before the {@link Future} has been
     * resolved.
     *
     * @param hashes
     *         the {@link Hash} array to be hashed, not null
     * @return a {@link Future} that when resolved will return the computed {@link Hash}, not null
     * @throws IllegalArgumentException
     *         if the {@code hashes} parameter is null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     * @see #getDefaultAlgorithm()
     */
    default Future<Hash> digestAsync(@NotEmpty final Hash... hashes) {
        return digestAsync(getDefaultAlgorithm(), hashes);
    }

    /**
     * Asynchronously computes the digest of the {@link Hash} array specified by the {@code hashes} parameter using the
     * hash algorithm specified by the {@code algorithm} parameter.
     *
     * <p>
     * Care must be taken to ensure the provided byte array is not modified before the {@link Future} has been
     * resolved.
     *
     * @param algorithm
     *         the algorithm to use, not null
     * @param hashes
     *         the {@link Hash} array to be hashed, not null
     * @return a {@link Future} that when resolved will return the computed {@link Hash}, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm} or the {@code hashes} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     */
    Future<Hash> digestAsync(@NotNull final HashAlgorithm algorithm, @NotEmpty final Hash... hashes);

    /**
     * Asynchronously computes the digest of the {@link ByteBuffer} specified by the {@code buffer} parameter. This
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
     * @param buffer
     *         the {@link ByteBuffer} to be hashed, not null
     * @return a {@link Future} that when resolved will return the computed {@link Hash}, not null
     * @throws IllegalArgumentException
     *         if the {@code buffer} parameter is null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     * @see #getDefaultAlgorithm()
     */
    default Future<Hash> digestAsync(@NotNull final ByteBuffer buffer) {
        return digestAsync(getDefaultAlgorithm(), buffer);
    }

    /**
     * Asynchronously computes the digest of the {@link ByteBuffer} specified by the {@code buffer} parameter using the
     * hash algorithm specified by the {@code algorithm} parameter.
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
     * @param buffer
     *         the {@link ByteBuffer} to be hashed, not null
     * @return a {@link Future} that when resolved will return the computed {@link Hash}, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm} or the {@code buffer} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     */
    Future<Hash> digestAsync(@NotNull final HashAlgorithm algorithm, @NotNull final ByteBuffer buffer);

    /**
     * Synchronously computes the digest of the {@link InputStream} specified by the {@code stream} parameter. This
     * implementation uses the default algorithm provided by the {@link #getDefaultAlgorithm()} method.
     *
     * <p>
     * This implementation will read the input stream from the current position until the end of the stream is reached
     * or no more bytes are available.
     *
     * @param stream
     *         the stream to be hashed, not null
     * @return the computed hash, not null
     * @throws IllegalArgumentException
     *         if the {@code stream} parameter is null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     * @see #getDefaultAlgorithm()
     */
    default Hash digestSync(@NotNull final InputStream stream) {
        return digestSync(getDefaultAlgorithm(), stream);
    }

    /**
     * Synchronously computes the digest of the {@link InputStream} specified by the {@code stream} parameter using the
     * hash algorithm specified by the {@code algorithm} parameter.
     *
     * <p>
     * This implementation will read the input stream from the current position until the end of the stream is reached
     * or no more bytes are available.
     *
     * @param algorithm
     *         the algorithm to use, not null
     * @param stream
     *         the stream to be hashed, not null
     * @return the computed hash, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm} or the {@code stream} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     */
    Hash digestSync(@NotNull final HashAlgorithm algorithm, @NotNull final InputStream stream);

    /**
     * Synchronously computes the digest of the byte array specified by the {@code data} parameter. This implementation
     * uses the default algorithm provided by the {@link #getDefaultAlgorithm()} method.
     *
     * <p>
     * This implementation will compute the hash of the entire byte array provided by the {@code data} parameter.
     *
     * @param data
     *         the byte array to be hashed, not null
     * @return the computed hash, not null
     * @throws IllegalArgumentException
     *         if the {@code data} parameter is null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     * @see #getDefaultAlgorithm()
     */
    default Hash digestSync(@NotNull final byte[] data) {
        return digestSync(getDefaultAlgorithm(), data);
    }

    /**
     * Synchronously computes the digest of the byte array specified by the {@code data} parameter using the hash
     * algorithm specified by the {@code algorithm} parameter.
     *
     * <p>
     * This implementation will compute the hash of the entire byte array provided by the {@code data} parameter.
     *
     * @param algorithm
     *         the algorithm to use, not null
     * @param data
     *         the byte array to be hashed, not null
     * @return the computed hash, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm} or the {@code data} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     */
    Hash digestSync(@NotNull final HashAlgorithm algorithm, @NotNull final byte[] data);

    /**
     * Synchronously computes the digest of the {@link Hash} array specified by the {@code hashes} parameter. This
     * implementation uses the default algorithm provided by the {@link #getDefaultAlgorithm()} method.
     *
     * @param hashes
     *         the {@link Hash} array to be hashed, not null
     * @return the computed hash, not null
     * @throws IllegalArgumentException
     *         if the {@code hashes} parameter is null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     * @see #getDefaultAlgorithm()
     */
    default Hash digestSync(@NotEmpty final Hash... hashes) {
        return digestSync(getDefaultAlgorithm(), hashes);
    }

    /**
     * Synchronously computes the digest of the {@link Hash} array specified by the {@code hashes} parameter using the
     * hash algorithm specified by the {@code algorithm} parameter.
     *
     * @param algorithm
     *         the algorithm to use, not null
     * @param hashes
     *         the {@link Hash} array to be hashed, not null
     * @return the computed hash, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm} or the {@code hashes} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     */
    Hash digestSync(@NotNull final HashAlgorithm algorithm, @NotEmpty final Hash... hashes);

    /**
     * Synchronously computes the digest of the {@link ByteBuffer} specified by the {@code buffer} parameter. This
     * implementation uses the default algorithm provided by the {@link #getDefaultAlgorithm()} method.
     *
     * <p>
     * This implementation will read the {@link ByteBuffer} from the current position until the end of the buffer is
     * reached.
     *
     * @param buffer
     *         the {@link ByteBuffer} to be hashed, not null
     * @return the computed hash, not null
     * @throws IllegalArgumentException
     *         if the {@code buffer} parameter is null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     * @see #getDefaultAlgorithm()
     */
    default Hash digestSync(@NotNull final ByteBuffer buffer) {
        return digestSync(getDefaultAlgorithm(), buffer);
    }

    /**
     * Synchronously computes the digest of the {@link ByteBuffer} specified by the {@code buffer} parameter using the
     * hash algorithm specified by the {@code algorithm} parameter.
     *
     * <p>
     * This implementation will read the {@link ByteBuffer} from the current position until the end of the buffer is
     * reached.
     *
     * @param algorithm
     *         the algorithm to use, not null
     * @param buffer
     *         the {@link ByteBuffer} to be hashed, not null
     * @return the computed hash, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm} or the {@code buffer} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the hash value
     */
    Hash digestSync(@NotNull final HashAlgorithm algorithm, @NotNull final ByteBuffer buffer);
}
