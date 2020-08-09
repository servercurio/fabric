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

public class MockHashable extends AbstractHashable {

    private final byte[] content;

    public MockHashable(final byte[] content) {
        this.content = content;
    }

    public MockHashable(final HashAlgorithm algorithm, final byte[] content) {
        super(algorithm);
        this.content = content;
    }

    public MockHashable(final HashAlgorithm algorithm, final Cryptography cryptography, final byte[] content) {
        super(algorithm, cryptography);
        this.content = content;
    }

    @Override
    protected Hash computeHash(final HashAlgorithm algorithm, final Cryptography cryptography) {
        return cryptography.digest().digestSync(algorithm, content);
    }

}
