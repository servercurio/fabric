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

public class Version implements Comparable<Version> {
    private int major;
    private int minor;
    private int build;
    private int revision;

    public Version(final int major, final int minor, final int build, final int revision) {
        this.major = major;
        this.minor = minor;
        this.build = build;
        this.revision = revision;
    }

    public int getMajor() {
        return major;
    }

    public int getMinor() {
        return minor;
    }

    public int getBuild() {
        return build;
    }

    public int getRevision() {
        return revision;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;

        if (!(o instanceof Version)) return false;

        final Version version = (Version) o;

        return new EqualsBuilder()
                .append(major, version.major)
                .append(minor, version.minor)
                .append(build, version.build)
                .append(revision, version.revision)
                .isEquals();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37)
                .append(major)
                .append(minor)
                .append(build)
                .append(revision)
                .toHashCode();
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.JSON_STYLE)
                .append("major", major)
                .append("minor", minor)
                .append("build", build)
                .append("revision", revision)
                .toString();
    }

    @Override
    public int compareTo(final Version other) {
        if (this == other) return 0;

        if (other == null) return -1;

        return new CompareToBuilder()
                .append(major, other.major)
                .append(minor, other.minor)
                .append(build, other.build)
                .append(revision, other.revision)
                .toComparison();
    }
}
