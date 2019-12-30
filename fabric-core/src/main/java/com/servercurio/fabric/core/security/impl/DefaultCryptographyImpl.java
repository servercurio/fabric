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

package com.servercurio.fabric.core.security.impl;

import com.servercurio.fabric.core.security.Cryptography;
import com.servercurio.fabric.core.security.Hash;
import com.servercurio.fabric.core.security.HashAlgorithm;
import com.servercurio.fabric.core.security.Hashable;
import com.servercurio.fabric.core.serialization.ObjectSerializer;
import com.servercurio.fabric.core.serialization.SerializationAware;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

public class DefaultCryptographyImpl implements Cryptography {

      private static final DefaultCryptographyImpl INSTANCE = new DefaultCryptographyImpl();

      private static final int STREAM_BUFFER_SIZE = 8192;

      private static final ThreadLocal<HashMap<HashAlgorithm, MessageDigest>> hashAlgorithmCache = ThreadLocal
              .withInitial(HashMap::new);

      private static final ObjectSerializer objectSerializer = new ObjectSerializer();

      private DefaultCryptographyImpl() {

      }

      public static Cryptography getInstance() {
            return INSTANCE;
      }

      public static ThreadLocal<HashMap<HashAlgorithm, MessageDigest>> getHashAlgorithmCache() {
            return hashAlgorithmCache;
      }

      @Override
      public Hash digestSync(final InputStream stream) throws NoSuchAlgorithmException, IOException {
            return digestSync(HashAlgorithm.SHA_384, stream);
      }

      @Override
      public Hash digestSync(final HashAlgorithm algorithm, final InputStream stream) throws NoSuchAlgorithmException, IOException {
            final MessageDigest digest = acquireAlgorithm(algorithm);
            final byte[] buffer = new byte[STREAM_BUFFER_SIZE];

            int bytesRead = stream.readNBytes(buffer, 0, buffer.length);

            while (bytesRead > 0) {
                  digest.update(buffer, 0, bytesRead);
                  bytesRead = stream.readNBytes(buffer, 0, buffer.length);
            }

            return new Hash(algorithm, digest.digest());
      }

      @Override
      public Hash digestSync(final byte[] data) throws NoSuchAlgorithmException {
            return digestSync(HashAlgorithm.SHA_384, data);
      }

      @Override
      public Hash digestSync(final HashAlgorithm algorithm, final byte[] data) throws NoSuchAlgorithmException {
            final MessageDigest digest = acquireAlgorithm(algorithm);

            digest.update(data);
            return new Hash(algorithm, digest.digest());
      }

      @Override
      public Hash digestSync(final Hash leftHash, final Hash rightHash) throws NoSuchAlgorithmException {
            return digestSync(HashAlgorithm.SHA_384, leftHash, rightHash);
      }

      @Override
      public Hash digestSync(final HashAlgorithm algorithm, final Hash leftHash, final Hash rightHash) throws NoSuchAlgorithmException {
            final MessageDigest digest = acquireAlgorithm(algorithm);

            if (leftHash != null) {
                  digest.update(leftHash.getValue());
            } else {
                  digest.update(Hash.EMPTY.getValue());
            }

            if (rightHash != null) {
                  digest.update(rightHash.getValue());
            } else {
                  digest.update(Hash.EMPTY.getValue());
            }

            return new Hash(algorithm, digest.digest());
      }

      @Override
      public Hash digestSync(final ByteBuffer buffer) throws NoSuchAlgorithmException {
            return digestSync(HashAlgorithm.SHA_384, buffer);
      }

      @Override
      public Hash digestSync(final HashAlgorithm algorithm, final ByteBuffer buffer) throws NoSuchAlgorithmException {
            final MessageDigest digest = acquireAlgorithm(algorithm);

            digest.update(buffer);
            return new Hash(algorithm, digest.digest());
      }

      @Override
      public Hash digestSync(final SerializationAware serialObject) throws NoSuchAlgorithmException, IOException {
            return digestSync(HashAlgorithm.SHA_384, serialObject);
      }

      @Override
      public Hash digestSync(final HashAlgorithm algorithm, final SerializationAware serialObject) throws NoSuchAlgorithmException, IOException {
            if (serialObject == null) {
                  return digestSync(algorithm, Hash.EMPTY.getValue());
            }

            Hash objectHash;

            if (serialObject instanceof Hashable) {
                  objectHash = ((Hashable) serialObject).getHash();

                  if (objectHash != null) {
                        return objectHash;
                  }
            }

            try (final ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
                  try (final DataOutputStream dos = new DataOutputStream(bos)) {
                        objectSerializer.serialize(dos, serialObject);

                        dos.flush();
                        bos.flush();

                        objectHash = digestSync(algorithm, bos.toByteArray());

                        if (serialObject instanceof Hashable) {
                              ((Hashable) serialObject).setHash(objectHash);
                        }

                        return objectHash;
                  }
            }
      }

      protected MessageDigest acquireAlgorithm(final HashAlgorithm algorithm) throws NoSuchAlgorithmException {
            final HashMap<HashAlgorithm, MessageDigest> cache = hashAlgorithmCache.get();

            if (!cache.containsKey(algorithm)) {
                  cache.put(algorithm, algorithm.instance());
            }

            return cache.get(algorithm);
      }
}
