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

import com.servercurio.fabric.security.spi.CryptoPrimitiveSupplier;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import org.apache.commons.lang3.builder.CompareToBuilder;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import static com.servercurio.fabric.lang.ComparableConstants.EQUAL;
import static com.servercurio.fabric.lang.ComparableConstants.GREATER_THAN;
import static com.servercurio.fabric.lang.ComparableConstants.LESS_THAN;

public class CipherTransformation implements Comparable<CipherTransformation>, CryptoPrimitiveSupplier<Cipher> {

    private CipherAlgorithm algorithm;
    private CipherMode mode;
    private CipherPadding padding;

    //region Constructors
    public CipherTransformation() {
        this(CipherAlgorithm.AES);
    }

    public CipherTransformation(final CipherAlgorithm algorithm) {
        this(algorithm, CipherMode.GCM);
    }

    public CipherTransformation(final CipherAlgorithm algorithm, final CipherMode mode) {
        this(algorithm, mode, CipherPadding.NONE);
    }

    public CipherTransformation(final CipherAlgorithm algorithm, final CipherMode mode,
                                final CipherPadding padding) {
        if (algorithm == null) {
            throw new IllegalArgumentException("algorithm");
        }

        this.algorithm = algorithm;
        this.mode = mode;
        this.padding = padding;
    }
    //endregion

    //region Getters & Setters
    public CipherAlgorithm getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(final CipherAlgorithm algorithm) {
        if (algorithm == null) {
            throw new IllegalArgumentException("algorithm");
        }

        this.algorithm = algorithm;
    }

    public CipherMode getMode() {
        return mode;
    }

    public void setMode(final CipherMode mode) {
        this.mode = mode;
    }

    public CipherPadding getPadding() {
        return padding;
    }

    public void setPadding(final CipherPadding padding) {
        this.padding = padding;
    }

    //endregion


    //region Member Methods
    public Cipher instance() {
        try {
            return Cipher.getInstance(toCipherTransform());
        } catch (NoSuchPaddingException | NoSuchAlgorithmException ex) {
            throw new CryptographyException(ex);
        }
    }

    public Cipher instance(final String provider) {
        try {
            return Cipher.getInstance(toCipherTransform(), provider);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | NoSuchProviderException ex) {
            throw new CryptographyException(ex);
        }
    }

    public Cipher instance(final Provider provider) {
        try {
            return Cipher.getInstance(toCipherTransform(), provider);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException ex) {
            throw new CryptographyException(ex);
        }
    }

    private String toCipherTransform() {
        if (mode == null || padding == null) {
            return algorithm.algorithmName();
        }

        return String.format("%s/%s/%s", algorithm.algorithmName(), mode.modeName(), padding.paddingName());
    }
    //endregion

    //region ToString, Equals, HashCode, & CompareTo

    /**
     * {@inheritDoc}
     */
    @Override
    public int compareTo(final CipherTransformation that) {

        if (this == that) {
            return EQUAL;
        }

        if (that == null) {
            return GREATER_THAN;
        }

        return new CompareToBuilder()
                .append(algorithm, that.algorithm)
                .append(mode, that.mode)
                .append(padding, that.padding)
                .build();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37)
                .append(algorithm)
                .append(mode)
                .append(padding)
                .toHashCode();
    }


    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }

        if (!(o instanceof CipherTransformation)) {
            return false;
        }

        final CipherTransformation that = (CipherTransformation) o;

        return new EqualsBuilder()
                .append(algorithm, that.algorithm)
                .append(mode, that.mode)
                .append(padding, that.padding)
                .isEquals();
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.NO_CLASS_NAME_STYLE)
                .append("algorithm", algorithm)
                .append("mode", mode)
                .append("padding", padding)
                .toString();
    }
    //endregion
}
