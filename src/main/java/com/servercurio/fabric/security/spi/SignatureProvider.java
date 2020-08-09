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
import com.servercurio.fabric.security.Seal;
import com.servercurio.fabric.security.SignatureAlgorithm;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.concurrent.Future;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

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
     * Asynchronously computes the signature of the {@link InputStream} specified by the {@code stream} parameter. This
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
     *         the private key to use during the signature computation, not null
     * @param stream
     *         the stream to be signed, not null
     * @return a {@link Future} that when resolved will return the computed {@link Seal}, not null
     * @throws IllegalArgumentException
     *         if the {@code key} or {@code stream} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the signature
     * @see #getDefaultAlgorithm()
     */
    default Future<Seal> signAsync(@NotNull final PrivateKey key, @NotNull final InputStream stream) {
        return signAsync(getDefaultAlgorithm(), key, stream);
    }

    /**
     * Asynchronously computes the signature of the {@link InputStream} specified by the {@code stream} parameter using
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
     *         the private key to use during the signature computation, not null
     * @param stream
     *         the stream to be signed, not null
     * @return a {@link Future} that when resolved will return the computed {@link Seal}, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm}, {@code key}, or {@code stream} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the signature
     */
    Future<Seal> signAsync(@NotNull final SignatureAlgorithm algorithm, @NotNull final PrivateKey key,
                           @NotNull final InputStream stream);

    /**
     * Asynchronously computes the signature of the byte array specified by the {@code data} parameter. This
     * implementation uses the default algorithm provided by the {@link #getDefaultAlgorithm()} method.
     *
     * <p>
     * This implementation will compute the signature of the entire byte array provided by the {@code data} parameter.
     *
     * <p>
     * Care must be taken to ensure the provided byte array is not modified before the {@link Future} has been
     * resolved.
     *
     * @param key
     *         the private key to use during the signature computation, not null
     * @param data
     *         the byte array to be signed, not null
     * @return a {@link Future} that when resolved will return the computed {@link Seal}, not null
     * @throws IllegalArgumentException
     *         if the {@code key} or {@code data} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the signature
     * @see #getDefaultAlgorithm()
     */
    default Future<Seal> signAsync(@NotNull final PrivateKey key, @NotNull final byte[] data) {
        return signAsync(getDefaultAlgorithm(), key, data);
    }

    /**
     * Asynchronously computes the signature of the byte array specified by the {@code data} parameter using the hash
     * algorithm specified by the {@code algorithm} parameter.
     *
     * <p>
     * This implementation will compute the signature of the entire byte array provided by the {@code data} parameter.
     *
     * <p>
     * Care must be taken to ensure the provided byte array is not modified before the {@link Future} has been
     * resolved.
     *
     * @param algorithm
     *         the algorithm to use, not null
     * @param key
     *         the private key to use during the signature computation, not null
     * @param data
     *         the byte array to be signed, not null
     * @return a {@link Future} that when resolved will return the computed {@link Seal}, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm}, {@code key}, or {@code data} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the signature
     */
    Future<Seal> signAsync(@NotNull final SignatureAlgorithm algorithm, @NotNull final PrivateKey key,
                           @NotNull final byte[] data);

    /**
     * Asynchronously computes the signature of the {@link Hash} array specified by the {@code hashes} parameter. This
     * implementation uses the default algorithm provided by the {@link #getDefaultAlgorithm()} method.
     *
     * <p>
     * Care must be taken to ensure the provided {@link Hash} array is not modified before the {@link Future} has been
     * resolved.
     *
     * @param key
     *         the private key to use during the signature computation, not null
     * @param hashes
     *         the {@link Hash} array to be signed, not null
     * @return a {@link Future} that when resolved will return the computed {@link Seal}, not null
     * @throws IllegalArgumentException
     *         if the {@code key} or {@code hashes} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the signature
     * @see #getDefaultAlgorithm()
     */
    default Future<Seal> signAsync(@NotNull final PrivateKey key, @NotEmpty final Hash... hashes) {
        return signAsync(getDefaultAlgorithm(), key, hashes);
    }

    /**
     * Asynchronously computes the signature of the {@link Hash} array specified by the {@code hashes} parameter using
     * the hash algorithm specified by the {@code algorithm} parameter.
     *
     * <p>
     * Care must be taken to ensure the provided byte array is not modified before the {@link Future} has been
     * resolved.
     *
     * @param algorithm
     *         the algorithm to use, not null
     * @param key
     *         the private key to use during the signature computation, not null
     * @param hashes
     *         the {@link Hash} array to be signed, not null
     * @return a {@link Future} that when resolved will return the computed {@link Seal}, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm}, {@code key}, or {@code hashes} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the signature
     */
    Future<Seal> signAsync(@NotNull final SignatureAlgorithm algorithm, @NotNull final PrivateKey key,
                           @NotEmpty final Hash... hashes);

    /**
     * Asynchronously computes the signature of the {@link ByteBuffer} specified by the {@code buffer} parameter. This
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
     *         the private key to use during the signature computation, not null
     * @param buffer
     *         the {@link ByteBuffer} to be signed, not null
     * @return a {@link Future} that when resolved will return the computed {@link Seal}, not null
     * @throws IllegalArgumentException
     *         if the {@code key} or {@code buffer} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the signature
     * @see #getDefaultAlgorithm()
     */
    default Future<Seal> signAsync(@NotNull final PrivateKey key, @NotNull final ByteBuffer buffer) {
        return signAsync(getDefaultAlgorithm(), key, buffer);
    }

    /**
     * Asynchronously computes the signature of the {@link ByteBuffer} specified by the {@code buffer} parameter using
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
     *         the private key to use during the signature computation, not null
     * @param buffer
     *         the {@link ByteBuffer} to be signed, not null
     * @return a {@link Future} that when resolved will return the computed {@link Seal}, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm}, {@code key}, or {@code buffer} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the signature
     */
    Future<Seal> signAsync(@NotNull final SignatureAlgorithm algorithm, @NotNull final PrivateKey key,
                           @NotNull final ByteBuffer buffer);

    /**
     * Synchronously computes the signature of the {@link InputStream} specified by the {@code stream} parameter. This
     * implementation uses the default algorithm provided by the {@link #getDefaultAlgorithm()} method.
     *
     * <p>
     * This implementation will read the input stream from the current position until the end of the stream is reached
     * or no more bytes are available.
     *
     * @param key
     *         the private key to use during the signature computation, not null
     * @param stream
     *         the stream to be signed, not null
     * @return the computed {@link Seal}, not null
     * @throws IllegalArgumentException
     *         if the {@code key} or {@code stream} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the signature
     * @see #getDefaultAlgorithm()
     */
    default Seal signSync(@NotNull final PrivateKey key, @NotNull final InputStream stream) {
        return signSync(getDefaultAlgorithm(), key, stream);
    }

    /**
     * Synchronously computes the signature of the {@link InputStream} specified by the {@code stream} parameter using
     * the hash algorithm specified by the {@code algorithm} parameter.
     *
     * <p>
     * This implementation will read the input stream from the current position until the end of the stream is reached
     * or no more bytes are available.
     *
     * @param algorithm
     *         the algorithm to use, not null
     * @param key
     *         the private key to use during the signature computation, not null
     * @param stream
     *         the stream to be signed, not null
     * @return the computed {@link Seal}, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm}, {@code key}, or {@code stream} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the signature
     */
    Seal signSync(@NotNull final SignatureAlgorithm algorithm, @NotNull final PrivateKey key,
                  @NotNull final InputStream stream);

    /**
     * Synchronously computes the signature of the byte array specified by the {@code data} parameter. This
     * implementation uses the default algorithm provided by the {@link #getDefaultAlgorithm()} method.
     *
     * <p>
     * This implementation will compute the signature of the entire byte array provided by the {@code data} parameter.
     *
     * @param key
     *         the private key to use during the signature computation, not null
     * @param data
     *         the byte array to be signed, not null
     * @return the computed {@link Seal}, not null
     * @throws IllegalArgumentException
     *         if the {@code key} or {@code data} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the signature
     * @see #getDefaultAlgorithm()
     */
    default Seal signSync(@NotNull final PrivateKey key, @NotNull final byte[] data) {
        return signSync(getDefaultAlgorithm(), key, data);
    }

    /**
     * Synchronously computes the signature of the byte array specified by the {@code data} parameter using the hash
     * algorithm specified by the {@code algorithm} parameter.
     *
     * <p>
     * This implementation will compute the signature of the entire byte array provided by the {@code data} parameter.
     *
     * @param algorithm
     *         the algorithm to use, not null
     * @param key
     *         the private key to use during the signature computation, not null
     * @param data
     *         the byte array to be signed, not null
     * @return the computed {@link Seal}, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm}, {@code key}, or {@code data} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the signature
     */
    Seal signSync(@NotNull final SignatureAlgorithm algorithm, @NotNull final PrivateKey key,
                  @NotNull final byte[] data);

    /**
     * Synchronously computes the signature of the {@link Hash} array specified by the {@code hashes} parameter. This
     * implementation uses the default algorithm provided by the {@link #getDefaultAlgorithm()} method.
     *
     * @param key
     *         the private key to use during the signature computation, not null
     * @param hashes
     *         the {@link Hash} array to be signed, not null
     * @return the computed {@link Seal}, not null
     * @throws IllegalArgumentException
     *         if the {@code key} or {@code hashes} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the signature
     * @see #getDefaultAlgorithm()
     */
    default Seal signSync(@NotNull final PrivateKey key, @NotEmpty final Hash... hashes) {
        return signSync(getDefaultAlgorithm(), key, hashes);
    }

    /**
     * Synchronously computes the signature of the {@link Hash} array specified by the {@code hashes} parameter using
     * the hash algorithm specified by the {@code algorithm} parameter.
     *
     * @param algorithm
     *         the algorithm to use, not null
     * @param key
     *         the private key to use during the signature computation, not null
     * @param hashes
     *         the {@link Hash} array to be signed, not null
     * @return the computed {@link Seal}, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm}, {@code key}, or {@code hashes} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the signature
     */
    Seal signSync(@NotNull final SignatureAlgorithm algorithm, @NotNull final PrivateKey key,
                  @NotEmpty final Hash... hashes);

    /**
     * Synchronously computes the signature of the {@link ByteBuffer} specified by the {@code buffer} parameter. This
     * implementation uses the default algorithm provided by the {@link #getDefaultAlgorithm()} method.
     *
     * <p>
     * This implementation will read the {@link ByteBuffer} from the current position until the end of the buffer is
     * reached.
     *
     * @param key
     *         the private key to use during the signature computation, not null
     * @param buffer
     *         the {@link ByteBuffer} to be signed, not null
     * @return the computed {@link Seal}, not null
     * @throws IllegalArgumentException
     *         if the {@code key} or {@code buffer} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the signature
     * @see #getDefaultAlgorithm()
     */
    default Seal signSync(@NotNull final PrivateKey key, @NotNull final ByteBuffer buffer) {
        return signSync(getDefaultAlgorithm(), key, buffer);
    }

    /**
     * Synchronously computes the signature of the {@link ByteBuffer} specified by the {@code buffer} parameter using
     * the hash algorithm specified by the {@code algorithm} parameter.
     *
     * <p>
     * This implementation will read the {@link ByteBuffer} from the current position until the end of the buffer is
     * reached.
     *
     * @param algorithm
     *         the algorithm to use, not null
     * @param key
     *         the private key to use during the signature computation, not null
     * @param buffer
     *         the {@link ByteBuffer} to be signed, not null
     * @return the computed {@link Seal}, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm}, {@code key}, or {@code buffer} parameters are null
     * @throws CryptographyException
     *         if an error occurs while computing the signature
     */
    Seal signSync(@NotNull final SignatureAlgorithm algorithm, @NotNull final PrivateKey key,
                  @NotNull final ByteBuffer buffer);

    /**
     * Asynchronously verifies the signature against the {@link InputStream} specified by the {@code stream} parameter.
     *
     * <p>
     * This implementation will read the input stream from the current position until the end of the stream is reached
     * or no more bytes are available.
     *
     * <p>
     * Care must be taken to ensure the provided {@link InputStream} is not closed before the {@link Future} has been
     * resolved.
     *
     * @param seal
     *         the signature to use when verifying the data, not null
     * @param key
     *         the public key to use during the signature verification, not null
     * @param stream
     *         the stream to be verified, not null
     * @return a {@link Future} that when resolved will return true if the signature was validated successfully, not
     *         null
     * @throws IllegalArgumentException
     *         if the {@code seal}, {@code key} or {@code stream} parameters are null
     * @throws CryptographyException
     *         if an error occurs while verifying the signature
     */
    Future<Boolean> verifyAsync(@NotNull final Seal seal, @NotNull final PublicKey key,
                                @NotNull final InputStream stream);

    /**
     * Asynchronously verifies the signature against the byte array specified by the {@code data} parameter.
     *
     * <p>
     * This implementation will verify the signature of the entire byte array provided by the {@code data} parameter.
     *
     * <p>
     * Care must be taken to ensure the provided byte array is not modified before the {@link Future} has been
     * resolved.
     *
     * @param seal
     *         the signature to use when verifying the data, not null
     * @param key
     *         the public key to use during the signature verification, not null
     * @param data
     *         the byte array to be verified, not null
     * @return a {@link Future} that when resolved will return true if the signature was validated successfully, not
     *         null
     * @throws IllegalArgumentException
     *         if the {@code seal}, {@code key} or {@code data} parameters are null
     * @throws CryptographyException
     *         if an error occurs while verifying the signature
     */
    Future<Boolean> verifyAsync(@NotNull final Seal seal, @NotNull final PublicKey key, @NotNull final byte[] data);

    /**
     * Asynchronously verifies the signature against the {@link Hash} array specified by the {@code hashes} parameter.
     *
     * <p>
     * Care must be taken to ensure the provided {@link Hash} array is not modified before the {@link Future} has been
     * resolved.
     *
     * @param seal
     *         the signature to use when verifying the data, not null
     * @param key
     *         the public key to use during the signature verification, not null
     * @param hashes
     *         the {@link Hash} array to be verified, not null
     * @return a {@link Future} that when resolved will return true if the signature was validated successfully, not
     *         null
     * @throws IllegalArgumentException
     *         if the {@code seal}, {@code key} or {@code hashes} parameters are null
     * @throws CryptographyException
     *         if an error occurs while verifying the signature
     */
    Future<Boolean> verifyAsync(@NotNull final Seal seal, @NotNull final PublicKey key, @NotEmpty final Hash... hashes);

    /**
     * Asynchronously verifies the signature against the {@link ByteBuffer} specified by the {@code buffer} parameter.
     *
     * <p>
     * This implementation will read the {@link ByteBuffer} from the current position until the end of the buffer is
     * reached.
     *
     * <p>
     * Care must be taken to ensure the provided {@link ByteBuffer} is not modified before the {@link Future} has been
     * resolved.
     *
     * @param seal
     *         the signature to use when verifying the data, not null
     * @param key
     *         the public key to use during the signature verification, not null
     * @param buffer
     *         the {@link ByteBuffer} to be verified, not null
     * @return a {@link Future} that when resolved will return true if the signature was validated successfully, not
     *         null
     * @throws IllegalArgumentException
     *         if the {@code seal}, {@code key} or {@code buffer} parameters are null
     * @throws CryptographyException
     *         if an error occurs while verifying the signature
     */
    Future<Boolean> verifyAsync(@NotNull final Seal seal, @NotNull final PublicKey key,
                                @NotNull final ByteBuffer buffer);

    /**
     * Synchronously verifies the signature against the {@link InputStream} specified by the {@code stream} parameter.
     *
     * <p>
     * This implementation will read the input stream from the current position until the end of the stream is reached
     * or no more bytes are available.
     *
     * @param seal
     *         the signature to use when verifying the data, not null
     * @param key
     *         the public key to use during the signature verification, not null
     * @param stream
     *         the stream to be verified, not null
     * @return a true if the signature was validated successfully, not null
     * @throws IllegalArgumentException
     *         if the {@code seal}, {@code key} or {@code stream} parameters are null
     * @throws CryptographyException
     *         if an error occurs while verifying the signature
     */
    boolean verifySync(@NotNull final Seal seal, @NotNull final PublicKey key, @NotNull final InputStream stream);

    /**
     * Synchronously verifies the signature against the byte array specified by the {@code data} parameter.
     *
     * <p>
     * This implementation will verify the signature of the entire byte array provided by the {@code data} parameter.
     *
     * @param seal
     *         the signature to use when verifying the data, not null
     * @param key
     *         the public key to use during the signature verification, not null
     * @param data
     *         the byte array to be verified, not null
     * @return true if the signature was validated successfully, not null
     * @throws IllegalArgumentException
     *         if the {@code seal}, {@code key} or {@code data} parameters are null
     * @throws CryptographyException
     *         if an error occurs while verifying the signature
     */
    boolean verifySync(@NotNull final Seal seal, @NotNull final PublicKey key, @NotNull final byte[] data);

    /**
     * Synchronously verifies the signature against the {@link Hash} array specified by the {@code hashes} parameter.
     *
     * @param seal
     *         the signature to use when verifying the data, not null
     * @param key
     *         the public key to use during the signature verification, not null
     * @param hashes
     *         the {@link Hash} array to be verified, not null
     * @return true if the signature was validated successfully, not null
     * @throws IllegalArgumentException
     *         if the {@code seal}, {@code key} or {@code hashes} parameters are null
     * @throws CryptographyException
     *         if an error occurs while verifying the signature
     */
    boolean verifySync(@NotNull final Seal seal, @NotNull final PublicKey key, @NotEmpty final Hash... hashes);

    /**
     * Synchronously verifies the signature against the {@link ByteBuffer} specified by the {@code buffer} parameter.
     *
     * <p>
     * This implementation will read the {@link ByteBuffer} from the current position until the end of the buffer is
     * reached.
     *
     * @param seal
     *         the signature to use when verifying the data, not null
     * @param key
     *         the public key to use during the signature verification, not null
     * @param buffer
     *         the {@link ByteBuffer} to be verified, not null
     * @return true if the signature was validated successfully, not null
     * @throws IllegalArgumentException
     *         if the {@code seal}, {@code key} or {@code buffer} parameters are null
     * @throws CryptographyException
     *         if an error occurs while verifying the signature
     */
    boolean verifySync(@NotNull final Seal seal, @NotNull final PublicKey key, @NotNull final ByteBuffer buffer);
}
