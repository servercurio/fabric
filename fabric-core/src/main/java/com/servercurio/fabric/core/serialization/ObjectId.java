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

package com.servercurio.fabric.core.serialization;

import org.apache.commons.lang3.builder.*;

public class ObjectId implements Comparable<ObjectId> {

      private int namespace;
      private int identifier;

      public ObjectId(final int namespace, final int identifier) {
            this.namespace = namespace;
            this.identifier = identifier;
      }

      public int getNamespace() {
            return namespace;
      }

      public int getIdentifier() {
            return identifier;
      }

      @Override
      public int compareTo(final ObjectId other) {
            if (this == other) {
                  return 0;
            }

            if (other == null) {
                  return -1;
            }

            return new CompareToBuilder()
                    .append(namespace, other.namespace)
                    .append(identifier, other.identifier)
                    .toComparison();
      }

      @Override
      public int hashCode() {
            return new HashCodeBuilder(17, 37)
                    .append(namespace)
                    .append(identifier)
                    .toHashCode();
      }

      @Override
      public boolean equals(final Object o) {
            if (this == o) {
                  return true;
            }

            if (!(o instanceof ObjectId)) {
                  return false;
            }

            final ObjectId other = (ObjectId) o;

            return new EqualsBuilder()
                    .append(namespace, other.namespace)
                    .append(identifier, other.identifier)
                    .isEquals();
      }

      @Override
      public String toString() {
            return new ToStringBuilder(this, ToStringStyle.JSON_STYLE)
                    .append("namespace", namespace)
                    .append("identifier", identifier)
                    .toString();
      }
}
