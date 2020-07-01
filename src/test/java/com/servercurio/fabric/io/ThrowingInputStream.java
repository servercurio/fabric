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

package com.servercurio.fabric.io;

import java.io.BufferedInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

public class ThrowingInputStream extends BufferedInputStream {

    private static final long THROW_AFTER_BYTE_COUNT = 100;

    private long bytesRead;

    /**
     * Creates a {@code BufferedInputStream} and saves its  argument, the input stream {@code in}, for later use. An
     * internal buffer array is created and  stored in {@code buf}.
     *
     * @param in the underlying input stream.
     */
    public ThrowingInputStream(final InputStream in) {
        super(in);
    }

    /**
     * Creates a {@code BufferedInputStream} with the specified buffer size, and saves its  argument, the input stream
     * {@code in}, for later use.  An internal buffer array of length  {@code size} is created and stored in {@code
     * buf}.
     *
     * @param in   the underlying input stream.
     * @param size the buffer size.
     * @throws IllegalArgumentException if {@code size <= 0}.
     */
    public ThrowingInputStream(final InputStream in, final int size) {
        super(in, size);
    }

    /**
     * See the general contract of the {@code read} method of {@code InputStream}.
     *
     * @return the next byte of data, or {@code -1} if the end of the stream is reached.
     * @throws IOException if this input stream has been closed by invoking its {@link #close()} method, or an I/O error
     *                     occurs.
     * @see FilterInputStream#in
     */
    @Override
    public synchronized int read() throws IOException {
        incrementAndThrow(1);
        return super.read();
    }

    /**
     * Reads bytes from this byte-input stream into the specified byte array, starting at the given offset.
     *
     * <p> This method implements the general contract of the corresponding
     * <code>{@link InputStream#read(byte[], int, int) read}</code> method of
     * the <code>{@link InputStream}</code> class.  As an additional convenience, it attempts to read as many bytes as
     * possible by repeatedly invoking the {@code read} method of the underlying stream.  This iterated {@code read}
     * continues until one of the following conditions becomes true: <ul>
     *
     * <li> The specified number of bytes have been read,
     *
     * <li> The {@code read} method of the underlying stream returns
     * {@code -1}, indicating end-of-file, or
     *
     * <li> The {@code available} method of the underlying stream
     * returns zero, indicating that further input requests would block.
     *
     * </ul> If the first {@code read} on the underlying stream returns
     * {@code -1} to indicate end-of-file then this method returns {@code -1}.  Otherwise this method returns the number
     * of bytes actually read.
     *
     * <p> Subclasses of this class are encouraged, but not required, to
     * attempt to read as many bytes as possible in the same fashion.
     *
     * @param b   destination buffer.
     * @param off offset at which to start storing bytes.
     * @param len maximum number of bytes to read.
     * @return the number of bytes read, or {@code -1} if the end of the stream has been reached.
     * @throws IOException if this input stream has been closed by invoking its {@link #close()} method, or an I/O error
     *                     occurs.
     */
    @Override
    public synchronized int read(final byte[] b, final int off, final int len) throws IOException {
        return incrementAndThrow(super.read(b, off, len));
    }

    /**
     * See the general contract of the {@code skip} method of {@code InputStream}.
     *
     * @param n
     * @throws IOException if this input stream has been closed by invoking its {@link #close()} method, {@code
     *                     in.skip(n)} throws an IOException, or an I/O error occurs.
     */
    @Override
    public synchronized long skip(final long n) throws IOException {
        return incrementAndThrow(super.skip(n));
    }

    /**
     * Reads up to {@code b.length} bytes of data from this input stream into an array of bytes. This method blocks
     * until some input is available.
     * <p>
     * This method simply performs the call {@code read(b, 0, b.length)} and returns the  result. It is important that
     * it does
     * <i>not</i> do {@code in.read(b)} instead;
     * certain subclasses of  {@code FilterInputStream} depend on the implementation strategy actually used.
     *
     * @param b the buffer into which the data is read.
     * @return the total number of bytes read into the buffer, or {@code -1} if there is no more data because the end of
     * the stream has been reached.
     * @throws IOException if an I/O error occurs.
     * @see FilterInputStream#read(byte[], int, int)
     */
    @Override
    public int read(final byte[] b) throws IOException {
        return incrementAndThrow(super.read(b));
    }

    /**
     * Reads all remaining bytes from the input stream. This method blocks until all remaining bytes have been read and
     * end of stream is detected, or an exception is thrown. This method does not close the input stream.
     *
     * <p> When this stream reaches end of stream, further invocations of this
     * method will return an empty byte array.
     *
     * <p> Note that this method is intended for simple cases where it is
     * convenient to read all bytes into a byte array. It is not intended for reading input streams with large amounts
     * of data.
     *
     * <p> The behavior for the case where the input stream is <i>asynchronously
     * closed</i>, or the thread interrupted during the read, is highly input stream specific, and therefore not
     * specified.
     *
     * <p> If an I/O error occurs reading from the input stream, then it may do
     * so after some, but not all, bytes have been read. Consequently the input stream may not be at end of stream and
     * may be in an inconsistent state. It is strongly recommended that the stream be promptly closed if an I/O error
     * occurs.
     *
     * @return a byte array containing the bytes read from this input stream
     * @throws IOException      if an I/O error occurs
     * @throws OutOfMemoryError if an array of the required size cannot be allocated.
     * @implSpec This method invokes {@link #readNBytes(int)} with a length of {@link Integer#MAX_VALUE}.
     * @since 9
     */
    @Override
    public byte[] readAllBytes() throws IOException {
        final byte[] bytes = super.readAllBytes();
        incrementAndThrow(bytes.length);

        return bytes;
    }

    /**
     * Reads up to a specified number of bytes from the input stream. This method blocks until the requested number of
     * bytes have been read, end of stream is detected, or an exception is thrown. This method does not close the input
     * stream.
     *
     * <p> The length of the returned array equals the number of bytes read
     * from the stream. If {@code len} is zero, then no bytes are read and an empty byte array is returned. Otherwise,
     * up to {@code len} bytes are read from the stream. Fewer than {@code len} bytes may be read if end of stream is
     * encountered.
     *
     * <p> When this stream reaches end of stream, further invocations of this
     * method will return an empty byte array.
     *
     * <p> Note that this method is intended for simple cases where it is
     * convenient to read the specified number of bytes into a byte array. The total amount of memory allocated by this
     * method is proportional to the number of bytes read from the stream which is bounded by {@code len}. Therefore,
     * the method may be safely called with very large values of {@code len} provided sufficient memory is available.
     *
     * <p> The behavior for the case where the input stream is <i>asynchronously
     * closed</i>, or the thread interrupted during the read, is highly input stream specific, and therefore not
     * specified.
     *
     * <p> If an I/O error occurs reading from the input stream, then it may do
     * so after some, but not all, bytes have been read. Consequently the input stream may not be at end of stream and
     * may be in an inconsistent state. It is strongly recommended that the stream be promptly closed if an I/O error
     * occurs.
     *
     * @param len the maximum number of bytes to read
     * @return a byte array containing the bytes read from this input stream
     * @throws IllegalArgumentException if {@code length} is negative
     * @throws IOException              if an I/O error occurs
     * @throws OutOfMemoryError         if an array of the required size cannot be allocated.
     * @implNote The number of bytes allocated to read data from this stream and return the result is bounded by {@code
     * 2*(long)len}, inclusive.
     * @since 11
     */
    @Override
    public byte[] readNBytes(final int len) throws IOException {
        incrementAndThrow(len);
        return super.readNBytes(len);
    }

    /**
     * Reads the requested number of bytes from the input stream into the given byte array. This method blocks until
     * {@code len} bytes of input data have been read, end of stream is detected, or an exception is thrown. The number
     * of bytes actually read, possibly zero, is returned. This method does not close the input stream.
     *
     * <p> In the case where end of stream is reached before {@code len} bytes
     * have been read, then the actual number of bytes read will be returned. When this stream reaches end of stream,
     * further invocations of this method will return zero.
     *
     * <p> If {@code len} is zero, then no bytes are read and {@code 0} is
     * returned; otherwise, there is an attempt to read up to {@code len} bytes.
     *
     * <p> The first byte read is stored into element {@code b[off]}, the next
     * one in to {@code b[off+1]}, and so on. The number of bytes read is, at most, equal to {@code len}. Let <i>k</i>
     * be the number of bytes actually read; these bytes will be stored in elements {@code b[off]} through {@code
     * b[off+}<i>k</i>{@code -1]}, leaving elements {@code b[off+}<i>k</i> {@code ]} through {@code b[off+len-1]}
     * unaffected.
     *
     * <p> The behavior for the case where the input stream is <i>asynchronously
     * closed</i>, or the thread interrupted during the read, is highly input stream specific, and therefore not
     * specified.
     *
     * <p> If an I/O error occurs reading from the input stream, then it may do
     * so after some, but not all, bytes of {@code b} have been updated with data from the input stream. Consequently
     * the input stream and {@code b} may be in an inconsistent state. It is strongly recommended that the stream be
     * promptly closed if an I/O error occurs.
     *
     * @param b   the byte array into which the data is read
     * @param off the start offset in {@code b} at which the data is written
     * @param len the maximum number of bytes to read
     * @return the actual number of bytes read into the buffer
     * @throws IOException               if an I/O error occurs
     * @throws NullPointerException      if {@code b} is {@code null}
     * @throws IndexOutOfBoundsException If {@code off} is negative, {@code len} is negative, or {@code len} is greater
     *                                   than {@code b.length - off}
     * @since 9
     */
    @Override
    public int readNBytes(final byte[] b, final int off, final int len) throws IOException {
        return incrementAndThrow(super.readNBytes(b, off, len));
    }

    /**
     * Skips over and discards exactly {@code n} bytes of data from this input stream.  If {@code n} is zero, then no
     * bytes are skipped. If {@code n} is negative, then no bytes are skipped. Subclasses may handle the negative value
     * differently.
     *
     * <p> This method blocks until the requested number of bytes have been
     * skipped, end of file is reached, or an exception is thrown.
     *
     * <p> If end of stream is reached before the stream is at the desired
     * position, then an {@code EOFException} is thrown.
     *
     * <p> If an I/O error occurs, then the input stream may be
     * in an inconsistent state. It is strongly recommended that the stream be promptly closed if an I/O error occurs.
     *
     * @param n the number of bytes to be skipped.
     * @throws EOFException if end of stream is encountered before the stream can be positioned {@code n} bytes beyond
     *                      its position when this method was invoked.
     * @throws IOException  if the stream cannot be positioned properly or if an I/O error occurs.
     * @implNote Subclasses are encouraged to provide a more efficient implementation of this method.
     * @implSpec If {@code n} is zero or negative, then no bytes are skipped. If {@code n} is positive, the default
     * implementation of this method invokes {@link #skip(long) skip()} with parameter {@code n}.  If the return value
     * of {@code skip(n)} is non-negative and less than {@code n}, then {@link #read()} is invoked repeatedly until the
     * stream is {@code n} bytes beyond its position when this method was invoked or end of stream is reached.  If the
     * return value of {@code skip(n)} is negative or greater than {@code n}, then an {@code IOException} is thrown. Any
     * exception thrown by {@code skip()} or {@code read()} will be propagated.
     * @see InputStream#skip(long)
     */
    @Override
    public void skipNBytes(final long n) throws IOException {
        super.skipNBytes(n);
        incrementAndThrow(n);
    }

    private int incrementAndThrow(final long amount) throws IOException {
        bytesRead += amount;

        if (bytesRead >= THROW_AFTER_BYTE_COUNT) {
            throw new IOException("Number of bytes read exceeded limit: " + THROW_AFTER_BYTE_COUNT);
        }

        return (int) amount;
    }
}
