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

package com.servercurio.fabric.core.serialization.spi;

import com.servercurio.fabric.core.serialization.ObjectId;
import com.servercurio.fabric.core.serialization.SerializationAware;
import com.servercurio.fabric.core.serialization.Version;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public abstract class AbstractSerializationProvider implements SerializationProvider {

    private Map<ObjectId, Set<Version>> supportedIdMap;
    private Set<Class<? extends SerializationAware>> supportedClassSet;

    public AbstractSerializationProvider() {
        this.supportedIdMap = new HashMap<>();
        this.supportedClassSet = new HashSet<>();

        handleObjectRegistration();
    }

    protected void registerObject(final ObjectId objectId, final Class<? extends SerializationAware> awareClass, final Set<Version> versions) {
        supportedIdMap.put(objectId, versions);
        supportedClassSet.add(awareClass);
    }

    protected abstract void handleObjectRegistration();

    @Override
    public <T extends SerializationAware> boolean isSupported(final T object) {
        if (object == null) {
            return false;
        }

        for (Class<? extends SerializationAware> clazz : supportedClassSet) {
            if (clazz.isInstance(object)) {
                return true;
            }
        }

        return false;
    }

    @Override
    public boolean isSupported(final ObjectId objectId, final Version version) {

        final Set<Version> versions = supportedIdMap.get(objectId);

        if (versions == null || versions.size() == 0) {
            return false;
        }

        return versions.contains(version);
    }

    @Override
    public <T extends SerializationAware> T newInstance(final ObjectId objectId, final Version version) {
        throw new UnsupportedOperationException();
    }
}
