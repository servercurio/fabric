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

import com.servercurio.fabric.security.CipherAlgorithm;
import com.servercurio.fabric.security.CipherMode;
import com.servercurio.fabric.security.CipherPadding;
import com.servercurio.fabric.security.CipherTransformation;
import com.servercurio.fabric.security.Cryptography;
import com.servercurio.fabric.security.CryptographyException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.PrivateKey;
import java.util.concurrent.Future;
import javax.crypto.SecretKey;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

/**
 * {@code Fabric Unified Cryptography API} provider definition that encapsulates all of the available symmetric and
 * asymmetric encryption functionality. The default algorithm is {@link CipherAlgorithm#AES} using {@link
 * CipherMode#GCM} mode and {@link CipherPadding#NONE} padding which is the minimum recommended algorithm that is C-NSA
 * compliant. Provider implementations may choose to override the default; however, it is recommended that the default
 * algorithm be a C-NSA compliant algorithm.
 *
 * @author Nathan Klick
 * @see Cryptography
 * @see CipherTransformation
 * @see CipherAlgorithm
 * @see CipherMode
 * @see CipherPadding
 */
public interface EncryptionProvider {

    /**
     * Returns the default algorithm. This is the algorithm that will be used when calling the overloaded methods that
     * do not accept the algorithm as a parameter.
     *
     * @return the default algorithm, not null
     */
    default CipherTransformation getDefaultAlgorithm() {
        return new CipherTransformation();
    }

    /**
     * Asynchronously decrypts the cipher text read from the {@link InputStream} specified by the {@code cipherStream}
     * parameter and writes the resulting clear text to the {@link OutputStream} specified by the {@code clearStream}
     * parameter. This implementation uses the default algorithm provided by the {@link #getDefaultAlgorithm()} method.
     *
     * <p>
     * This implementation will read the input stream from the current position until the end of the stream is reached
     * or no more bytes are available.
     *
     * <p>
     * Care must be taken to ensure the provided {@link InputStream} and {@link OutputStream} are not closed before the
     * {@link Future} has been resolved.
     *
     * @param key
     *         the {@link SecretKey} or {@link PrivateKey} to be used to decrypt the cipher text, not null
     * @param iv
     *         the original nonce used during the encryption of the cipher text, not null
     * @param cipherStream
     *         the input stream containing the cipher text to be decrypted, not null
     * @param clearStream
     *         the output stream where the clear text will be written, not null
     * @return a {@link Future} that when resolved indicates that the operation is complete
     * @throws IllegalArgumentException
     *         if the {@code key}, {@code iv}, {@code cipherStream}, or {@code clearStream} parameters are null
     * @throws CryptographyException
     *         if an error occurs while performing the decryption operation
     * @see #getDefaultAlgorithm()
     */
    default Future<?> decryptAsync(@NotNull final Key key,
                                   @NotEmpty final byte[] iv,
                                   @NotNull final InputStream cipherStream,
                                   @NotNull final OutputStream clearStream) {
        return decryptAsync(getDefaultAlgorithm(), key, iv, cipherStream, clearStream);
    }

    /**
     * Asynchronously decrypts the cipher text read from the {@link InputStream} specified by the {@code cipherStream}
     * parameter and writes the resulting clear text to the {@link OutputStream} specified by the {@code clearStream}
     * parameter.
     *
     * <p>
     * This implementation will read the input stream from the current position until the end of the stream is reached
     * or no more bytes are available.
     *
     * <p>
     * Care must be taken to ensure the provided {@link InputStream} and {@link OutputStream} are not closed before the
     * {@link Future} has been resolved.
     *
     * @param algorithm
     *         the algorithm to use, not null
     * @param key
     *         the {@link SecretKey} or {@link PrivateKey} to be used to decrypt the cipher text, not null
     * @param iv
     *         the original nonce used during the encryption of the cipher text, not null
     * @param cipherStream
     *         the input stream containing the cipher text to be decrypted, not null
     * @param clearStream
     *         the output stream where the clear text will be written, not null
     * @return a {@link Future} that when resolved indicates that the operation is complete
     * @throws IllegalArgumentException
     *         if the {@code algorithm}, {@code key}, {@code iv}, {@code cipherStream}, or {@code clearStream}
     *         parameters are null
     * @throws CryptographyException
     *         if an error occurs while performing the decryption operation
     */
    Future<?> decryptAsync(@NotNull final CipherTransformation algorithm,
                           @NotNull final Key key,
                           @NotEmpty final byte[] iv,
                           @NotNull final InputStream cipherStream,
                           @NotNull final OutputStream clearStream);

    /**
     * Asynchronously decrypts the cipher text read from the byte array specified by the {@code data} parameter and
     * returns a {@link Future} that when resolved returns the byte array containing the clear text. This implementation
     * uses the default algorithm provided by the {@link #getDefaultAlgorithm()} method.
     *
     * <p>
     * This implementation will read the entire byte array provided by the {@code data} parameter.
     *
     * <p>
     * Care must be taken to ensure the provided byte array is not modified before the {@link Future} has been
     * resolved.
     *
     * @param key
     *         the {@link SecretKey} or {@link PrivateKey} to be used to decrypt the cipher text, not null
     * @param iv
     *         the original nonce used during the encryption of the cipher text, not null
     * @param data
     *         the byte array containing the cipher text to be decrypted, not null
     * @return a {@link Future} that when resolved returns the byte array containing the clear text
     * @throws IllegalArgumentException
     *         if the {@code key}, {@code iv}, or {@code data} parameters are null
     * @throws CryptographyException
     *         if an error occurs while performing the decryption operation
     * @see #getDefaultAlgorithm()
     */
    default Future<byte[]> decryptAsync(@NotNull final Key key, @NotEmpty final byte[] iv,
                                        @NotEmpty final byte[] data) {
        return decryptAsync(getDefaultAlgorithm(), key, iv, data);
    }

    /**
     * Asynchronously decrypts the cipher text read from the byte array specified by the {@code data} parameter and
     * returns a {@link Future} that when resolved returns the byte array containing the clear text.
     *
     * <p>
     * This implementation will read the entire byte array provided by the {@code data} parameter.
     *
     * <p>
     * Care must be taken to ensure the provided byte array is not modified before the {@link Future} has been
     * resolved.
     *
     * @param algorithm
     *         the algorithm to use, not null
     * @param key
     *         the {@link SecretKey} or {@link PrivateKey} to be used to decrypt the cipher text, not null
     * @param iv
     *         the original nonce used during the encryption of the cipher text, not null
     * @param data
     *         the byte array containing the cipher text to be decrypted, not null
     * @return a {@link Future} that when resolved returns the byte array containing the clear text
     * @throws IllegalArgumentException
     *         if the {@code algorithm}, {@code key}, {@code iv}, or {@code data} parameters are null
     * @throws CryptographyException
     *         if an error occurs while performing the decryption operation
     */
    Future<byte[]> decryptAsync(@NotNull final CipherTransformation algorithm,
                                @NotNull final Key key,
                                @NotEmpty final byte[] iv,
                                @NotEmpty final byte[] data);

    /**
     * Asynchronously decrypts the cipher text read from the {@link ByteBuffer} specified by the {@code buffer}
     * parameter and returns a {@link Future} that when resolved returns the {@link ByteBuffer} containing the clear
     * text. This implementation uses the default algorithm provided by the {@link #getDefaultAlgorithm()} method.
     *
     * <p>
     * This implementation will read the entire {@link ByteBuffer} provided by the {@code buffer} parameter.
     *
     * <p>
     * Care must be taken to ensure the provided {@link ByteBuffer} is not modified before the {@link Future} has been
     * resolved.
     *
     * @param key
     *         the {@link SecretKey} or {@link PrivateKey} to be used to decrypt the cipher text, not null
     * @param iv
     *         the original nonce used during the encryption of the cipher text, not null
     * @param buffer
     *         the {@link ByteBuffer} containing the cipher text to be decrypted, not null
     * @return a {@link Future} that when resolved returns the {@link ByteBuffer} containing the clear text
     * @throws IllegalArgumentException
     *         if the {@code key}, {@code iv}, or {@code buffer} parameters are null
     * @throws CryptographyException
     *         if an error occurs while performing the decryption operation
     * @see #getDefaultAlgorithm()
     */
    default Future<ByteBuffer> decryptAsync(@NotNull final Key key, @NotEmpty final byte[] iv,
                                            @NotNull final ByteBuffer buffer) {
        return decryptAsync(getDefaultAlgorithm(), key, iv, buffer);
    }

    /**
     * Asynchronously decrypts the cipher text read from the {@link ByteBuffer} specified by the {@code buffer}
     * parameter and returns a {@link Future} that when resolved returns the {@link ByteBuffer} containing the clear
     * text.
     *
     * <p>
     * This implementation will read the entire {@link ByteBuffer} provided by the {@code buffer} parameter.
     *
     * <p>
     * Care must be taken to ensure the provided {@link ByteBuffer} is not modified before the {@link Future} has been
     * resolved.
     *
     * @param algorithm
     *         the algorithm to use, not null
     * @param key
     *         the {@link SecretKey} or {@link PrivateKey} to be used to decrypt the cipher text, not null
     * @param iv
     *         the original nonce used during the encryption of the cipher text, not null
     * @param buffer
     *         the {@link ByteBuffer} containing the cipher text to be decrypted, not null
     * @return a {@link Future} that when resolved returns the {@link ByteBuffer} containing the clear text
     * @throws IllegalArgumentException
     *         if the {@code algorithm}, {@code key}, {@code iv}, or {@code buffer} parameters are null
     * @throws CryptographyException
     *         if an error occurs while performing the decryption operation
     */
    Future<ByteBuffer> decryptAsync(@NotNull final CipherTransformation algorithm,
                                    @NotNull final Key key,
                                    @NotEmpty final byte[] iv,
                                    @NotNull final ByteBuffer buffer);

    /**
     * Synchronously decrypts the cipher text read from the {@link InputStream} specified by the {@code cipherStream}
     * parameter and writes the resulting clear text to the {@link OutputStream} specified by the {@code clearStream}
     * parameter. This implementation uses the default algorithm provided by the {@link #getDefaultAlgorithm()} method.
     *
     * <p>
     * This implementation will read the input stream from the current position until the end of the stream is reached
     * or no more bytes are available.
     *
     * @param key
     *         the {@link SecretKey} or {@link PrivateKey} to be used to decrypt the cipher text, not null
     * @param iv
     *         the original nonce used during the encryption of the cipher text, not null
     * @param cipherStream
     *         the input stream containing the cipher text to be decrypted, not null
     * @param clearStream
     *         the output stream where the clear text will be written, not null
     * @throws IllegalArgumentException
     *         if the {@code key}, {@code iv}, {@code cipherStream}, or {@code clearStream} parameters are null
     * @throws CryptographyException
     *         if an error occurs while performing the decryption operation
     * @see #getDefaultAlgorithm()
     */
    default void decryptSync(@NotNull final Key key, @NotEmpty final byte[] iv, @NotNull final InputStream cipherStream,
                             @NotNull final OutputStream clearStream) {
        decryptSync(getDefaultAlgorithm(), key, iv, cipherStream, clearStream);
    }

    /**
     * Synchronously decrypts the cipher text read from the {@link InputStream} specified by the {@code cipherStream}
     * parameter and writes the resulting clear text to the {@link OutputStream} specified by the {@code clearStream}
     * parameter.
     *
     * <p>
     * This implementation will read the input stream from the current position until the end of the stream is reached
     * or no more bytes are available.
     *
     * @param algorithm
     *         the algorithm to use, not null
     * @param key
     *         the {@link SecretKey} or {@link PrivateKey} to be used to decrypt the cipher text, not null
     * @param iv
     *         the original nonce used during the encryption of the cipher text, not null
     * @param cipherStream
     *         the input stream containing the cipher text to be decrypted, not null
     * @param clearStream
     *         the output stream where the clear text will be written, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm}, {@code key}, {@code iv}, {@code cipherStream}, or {@code clearStream}
     *         parameters are null
     * @throws CryptographyException
     *         if an error occurs while performing the decryption operation
     */
    void decryptSync(@NotNull final CipherTransformation algorithm,
                     @NotNull final Key key,
                     @NotEmpty final byte[] iv,
                     @NotNull final InputStream cipherStream,
                     @NotNull final OutputStream clearStream);

    /**
     * Synchronously decrypts the cipher text read from the byte array specified by the {@code data} parameter and
     * returns the byte array containing the clear text. This implementation uses the default algorithm provided by the
     * {@link #getDefaultAlgorithm()} method.
     *
     * <p>
     * This implementation will read the entire byte array provided by the {@code data} parameter.
     *
     * @param key
     *         the {@link SecretKey} or {@link PrivateKey} to be used to decrypt the cipher text, not null
     * @param iv
     *         the original nonce used during the encryption of the cipher text, not null
     * @param data
     *         the byte array containing the cipher text to be decrypted, not null
     * @return a byte array containing the clear text, not null
     * @throws IllegalArgumentException
     *         if the {@code key}, {@code iv}, or {@code data} parameters are null
     * @throws CryptographyException
     *         if an error occurs while performing the decryption operation
     * @see #getDefaultAlgorithm()
     */
    default byte[] decryptSync(@NotNull final Key key, @NotEmpty final byte[] iv, @NotEmpty final byte[] data) {
        return decryptSync(getDefaultAlgorithm(), key, iv, data);
    }

    /**
     * Synchronously decrypts the cipher text read from the byte array specified by the {@code data} parameter and
     * returns the byte array containing the clear text.
     *
     * <p>
     * This implementation will read the entire byte array provided by the {@code data} parameter.
     *
     * @param algorithm
     *         the algorithm to use, not null
     * @param key
     *         the {@link SecretKey} or {@link PrivateKey} to be used to decrypt the cipher text, not null
     * @param iv
     *         the original nonce used during the encryption of the cipher text, not null
     * @param data
     *         the byte array containing the cipher text to be decrypted, not null
     * @return a byte array containing the clear text, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm}, {@code key}, {@code iv}, or {@code data} parameters are null
     * @throws CryptographyException
     *         if an error occurs while performing the decryption operation
     */
    byte[] decryptSync(@NotNull final CipherTransformation algorithm,
                       @NotNull final Key key,
                       @NotEmpty final byte[] iv,
                       @NotEmpty final byte[] data);

    /**
     * Synchronously decrypts the cipher text read from the {@link ByteBuffer} specified by the {@code buffer} parameter
     * and returns the {@link ByteBuffer} containing the clear text. This implementation uses the default algorithm
     * provided by the {@link #getDefaultAlgorithm()} method.
     *
     * <p>
     * This implementation will read the entire {@link ByteBuffer} provided by the {@code buffer} parameter.
     *
     * @param key
     *         the {@link SecretKey} or {@link PrivateKey} to be used to decrypt the cipher text, not null
     * @param iv
     *         the original nonce used during the encryption of the cipher text, not null
     * @param buffer
     *         the {@link ByteBuffer} containing the cipher text to be decrypted, not null
     * @return a {@link ByteBuffer} containing the clear text, not null
     * @throws IllegalArgumentException
     *         if the {@code key}, {@code iv}, or {@code buffer} parameters are null
     * @throws CryptographyException
     *         if an error occurs while performing the decryption operation
     * @see #getDefaultAlgorithm()
     */
    default ByteBuffer decryptSync(@NotNull final Key key, @NotEmpty final byte[] iv,
                                   @NotNull final ByteBuffer buffer) {
        return decryptSync(getDefaultAlgorithm(), key, iv, buffer);
    }

    /**
     * Synchronously decrypts the cipher text read from the {@link ByteBuffer} specified by the {@code buffer} parameter
     * and returns the {@link ByteBuffer} containing the clear text.
     *
     * <p>
     * This implementation will read the entire {@link ByteBuffer} provided by the {@code buffer} parameter.
     *
     * @param algorithm
     *         the algorithm to use, not null
     * @param key
     *         the {@link SecretKey} or {@link PrivateKey} to be used to decrypt the cipher text, not null
     * @param iv
     *         the original nonce used during the encryption of the cipher text, not null
     * @param buffer
     *         the {@link ByteBuffer} containing the cipher text to be decrypted, not null
     * @return a {@link ByteBuffer} containing the clear text, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm}, {@code key}, {@code iv}, or {@code buffer} parameters are null
     * @throws CryptographyException
     *         if an error occurs while performing the decryption operation
     */
    ByteBuffer decryptSync(@NotNull final CipherTransformation algorithm,
                           @NotNull final Key key,
                           @NotEmpty final byte[] iv,
                           @NotNull final ByteBuffer buffer);

    /**
     * @param key
     * @param iv
     * @param clearStream
     * @param cipherStream
     * @return
     */
    default Future<?> encryptAsync(final Key key, final byte[] iv, final InputStream clearStream,
                                   final OutputStream cipherStream) {
        return encryptAsync(getDefaultAlgorithm(), key, iv, clearStream, cipherStream);
    }

    /**
     * @param algorithm
     * @param key
     * @param iv
     * @param clearStream
     * @param cipherStream
     * @return
     */
    Future<?> encryptAsync(final CipherTransformation algorithm, final Key key, final byte[] iv,
                           final InputStream clearStream, final OutputStream cipherStream);

    /**
     * @param key
     * @param iv
     * @param data
     * @return
     */
    default Future<byte[]> encryptAsync(final Key key, final byte[] iv, final byte[] data) {
        return encryptAsync(getDefaultAlgorithm(), key, iv, data);
    }

    /**
     * @param algorithm
     * @param key
     * @param iv
     * @param data
     * @return
     */
    Future<byte[]> encryptAsync(final CipherTransformation algorithm, final Key key, final byte[] iv,
                                final byte[] data);

    /**
     * @param key
     * @param iv
     * @param buffer
     * @return
     */
    default Future<ByteBuffer> encryptAsync(final Key key, final byte[] iv, final ByteBuffer buffer) {
        return encryptAsync(getDefaultAlgorithm(), key, iv, buffer);
    }

    /**
     * @param algorithm
     * @param key
     * @param iv
     * @param buffer
     * @return
     */
    Future<ByteBuffer> encryptAsync(final CipherTransformation algorithm, final Key key, final byte[] iv,
                                    final ByteBuffer buffer);

    /**
     * @param key
     * @param iv
     * @param clearStream
     * @param cipherStream
     */
    default void encryptSync(final Key key, final byte[] iv, final InputStream clearStream,
                             final OutputStream cipherStream) {
        encryptSync(getDefaultAlgorithm(), key, iv, clearStream, cipherStream);
    }

    /**
     * @param algorithm
     * @param key
     * @param iv
     * @param clearStream
     * @param cipherStream
     */
    void encryptSync(final CipherTransformation algorithm, final Key key, final byte[] iv,
                     final InputStream clearStream, final OutputStream cipherStream);

    /**
     * @param key
     * @param iv
     * @param data
     * @return
     */
    default byte[] encryptSync(final Key key, final byte[] iv, final byte[] data) {
        return encryptSync(getDefaultAlgorithm(), key, iv, data);
    }

    /**
     * @param algorithm
     * @param key
     * @param iv
     * @param data
     * @return
     */
    byte[] encryptSync(final CipherTransformation algorithm, final Key key, final byte[] iv, final byte[] data);

    /**
     * @param key
     * @param iv
     * @param buffer
     * @return
     */
    default ByteBuffer encryptSync(final Key key, final byte[] iv, final ByteBuffer buffer) {
        return encryptSync(getDefaultAlgorithm(), key, iv, buffer);
    }

    /**
     * @param algorithm
     * @param key
     * @param iv
     * @param buffer
     * @return
     */
    ByteBuffer encryptSync(final CipherTransformation algorithm, final Key key, final byte[] iv,
                           final ByteBuffer buffer);

    /**
     * @return
     */
    default Future<byte[]> nonceAsync() {
        return nonceAsync(getDefaultAlgorithm());
    }

    /**
     * @param algorithm
     * @return
     */
    Future<byte[]> nonceAsync(final CipherTransformation algorithm);

    /**
     * @return
     */
    default byte[] nonceSync() {
        return nonceSync(getDefaultAlgorithm());
    }

    /**
     * @param algorithm
     * @return
     */
    byte[] nonceSync(final CipherTransformation algorithm);
}
