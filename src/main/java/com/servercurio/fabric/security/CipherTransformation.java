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
import javax.validation.constraints.NotNull;
import org.apache.commons.lang3.builder.CompareToBuilder;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import static com.servercurio.fabric.lang.ComparableConstants.EQUAL;
import static com.servercurio.fabric.lang.ComparableConstants.GREATER_THAN;

public class CipherTransformation implements Comparable<CipherTransformation>, CryptoPrimitiveSupplier<Cipher> {

    @NotNull
    private CipherAlgorithm algorithm;

    private CipherMode mode;

    private CipherPadding padding;


    public CipherTransformation() {
        this(CipherAlgorithm.AES);
    }

    public CipherTransformation(@NotNull final CipherAlgorithm algorithm) {
        this(algorithm, CipherMode.GCM);
    }

    public CipherTransformation(@NotNull final CipherAlgorithm algorithm, final CipherMode mode) {
        this(algorithm, mode, CipherPadding.NONE);
    }

    public CipherTransformation(@NotNull final CipherAlgorithm algorithm, final CipherMode mode,
                                final CipherPadding padding) {
        if (algorithm == null) {
            throw new IllegalArgumentException("algorithm");
        }

        this.algorithm = algorithm;
        this.mode = mode;
        this.padding = padding;
    }

    public CipherAlgorithm getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(@NotNull final CipherAlgorithm algorithm) {
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

    /**
     * Gets the string representation of the algorithm name, mode, and padding in the format required by the {@link
     * Cipher#getInstance(String)} method and it's related variants.
     *
     * @return a fully formed {@link Cipher} name including mode and padding (if specified)
     */
    private String toCipherTransform() {
        if (mode == null || padding == null) {
            return algorithm.algorithmName();
        }

        return String.format("%s/%s/%s", algorithm.algorithmName(), mode.modeName(), padding.paddingName());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int compareTo(@NotNull final CipherTransformation that) {

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

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37)
                .append(algorithm)
                .append(mode)
                .append(padding)
                .toHashCode();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }

        if (o == null || (getClass() != o.getClass() && !o.getClass().isAssignableFrom(getClass()))) {
            return false;
        }

        final CipherTransformation that = (CipherTransformation) o;

        return new EqualsBuilder()
                .append(algorithm, that.algorithm)
                .append(mode, that.mode)
                .append(padding, that.padding)
                .isEquals();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.NO_CLASS_NAME_STYLE)
                .append("algorithm", algorithm)
                .append("mode", mode)
                .append("padding", padding)
                .toString();
    }

    /**
     * Creates an instance of the algorithm using the Java Cryptography Architecture and the default {@link Provider}
     * implementation.
     *
     * @return an instance of the algorithm implementation
     * @throws CryptographyException
     *         if an error occurs or the algorithm implementation was not available
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html">Java
     *         Cryptography Architecture</a>
     */
    public Cipher instance() {
        try {
            return Cipher.getInstance(toCipherTransform());
        } catch (NoSuchPaddingException | NoSuchAlgorithmException ex) {
            throw new CryptographyException(ex);
        }
    }

    /**
     * Creates an instance of the algorithm using the Java Cryptography Architecture and requesting the implementation
     * from the specified {@code provider}.
     *
     * @param provider
     *         the name of the provider from which to request the algorithm implementation, not null
     * @return an instance of the algorithm implementation
     * @throws CryptographyException
     *         if an error occurs, the algorithm implementation was not available, or the provider was not available
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html">Java
     *         Cryptography Architecture</a>
     */
    public Cipher instance(@NotNull final String provider) {
        try {
            return Cipher.getInstance(toCipherTransform(), provider);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | NoSuchProviderException ex) {
            throw new CryptographyException(ex);
        }
    }

    /**
     * Creates an instance of the algorithm using the Java Cryptography Architecture and requesting the implementation
     * from the specified {@code provider}.
     *
     * @param provider
     *         the provider instance from which to request the algorithm implementation, not null
     * @return an instance of the algorithm implementation
     * @throws CryptographyException
     *         if an error occurs or the algorithm implementation was not available
     * @see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html">Java
     *         Cryptography Architecture</a>
     */
    public Cipher instance(@NotNull final Provider provider) {
        try {
            return Cipher.getInstance(toCipherTransform(), provider);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException ex) {
            throw new CryptographyException(ex);
        }
    }
}
