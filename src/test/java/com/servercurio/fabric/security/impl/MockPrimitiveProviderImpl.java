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

package com.servercurio.fabric.security.impl;

import com.servercurio.fabric.security.CryptographyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class MockPrimitiveProviderImpl extends PrimitiveProviderImpl {

    /**
     * The default {@link SecureRandom} implementation to use for all instances.
     */
    private static final String SECURE_RANDOM_ALGORITHM = "NativePRNGNonBlocking";
    
    private static final ThreadLocal<SecureRandom> secureRandomCache =
            ThreadLocal.withInitial(MockPrimitiveProviderImpl::acquireRandom);

    public MockPrimitiveProviderImpl() {
        super();
    }

    /**
     * Factory method to create a new {@link SecureRandom} instance using the default algorithm specified by the {@link
     * #SECURE_RANDOM_ALGORITHM} constant.
     *
     * @return a new {@link SecureRandom} instance, not null
     */
    private static SecureRandom acquireRandom() {

        try {
            return SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM);
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptographyException(ex);
        }
    }

    @Override
    public SecureRandom random() {
        return secureRandomCache.get();
    }
}
