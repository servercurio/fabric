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

module com.servercurio.fabric {
    // General Purpose Exports
    exports com.servercurio.fabric.lang;

    // Imaging Exports
    exports com.servercurio.fabric.image.scalr;

    // Security Exports
    exports com.servercurio.fabric.security;
    exports com.servercurio.fabric.security.spi;


    // Apache Commons
    requires org.apache.commons.lang3;

    // Bouncy Castle
    requires org.bouncycastle.provider;

    // JSR-380 Validation
    requires java.validation;

    // Imaging Libraries
    requires metadata.extractor;

    // JDK Components
    requires java.desktop;

    // Service Providers
    uses com.servercurio.fabric.security.Cryptography;
    uses com.servercurio.fabric.security.spi.PrimitiveProvider;
    uses com.servercurio.fabric.security.spi.SignatureProvider;
    uses com.servercurio.fabric.security.spi.EncryptionProvider;
    uses com.servercurio.fabric.security.spi.MacProvider;
    uses com.servercurio.fabric.security.spi.DigestProvider;
    uses com.servercurio.fabric.security.spi.CryptoPrimitiveSupplier;

}