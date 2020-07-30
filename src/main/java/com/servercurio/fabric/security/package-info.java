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

/**
 * Contains all the core cryptographic functionality provided by the {@code Fabric} library. The {@link
 * com.servercurio.fabric.security.Cryptography} interface serves as the unified API for accessing the entire suite of
 * cryptographic methods. The {@link com.servercurio.fabric.security.Hash}, {@link
 * com.servercurio.fabric.security.ImmutableHash}, and {@link com.servercurio.fabric.security.Seal} implementations
 * serve as convenience wrappers for cryptographic hashes and signatures respectively. One of the major design goals is
 * to eliminate the need for users to maintain magic strings and constant value in order to access cryptographic
 * functions; therefore, this module provides enumerations for the most common secure cryptographic algorithms as
 * outlined below:
 * <p>
 * <ul>
 *     <li>{@link com.servercurio.fabric.security.HashAlgorithm}</li>
 *     <li>{@link com.servercurio.fabric.security.MacAlgorithm}</li>
 *     <li>{@link com.servercurio.fabric.security.SignatureAlgorithm}</li>
 *     <li>{@link com.servercurio.fabric.security.CipherAlgorithm}</li>
 *     <li>{@link com.servercurio.fabric.security.CipherMode}</li>
 *     <li>{@link com.servercurio.fabric.security.CipherPadding}</li>
 *     <li>{@link com.servercurio.fabric.security.CipherTransformation}</li>
 * </ul>
 *
 * @see com.servercurio.fabric.security.Cryptography
 */
package com.servercurio.fabric.security;