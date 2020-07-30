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

/**
 * Represents a complete cryptographic encryption transformation that includes the encryption algorithm, operational
 * mode, and padding mode.
 *
 * @author Nathan Klick
 * @see CipherAlgorithm
 * @see CipherMode
 * @see CipherPadding
 * @see Cryptography
 */
public class CipherTransformation implements Comparable<CipherTransformation>, CryptoPrimitiveSupplier<Cipher> {

    /**
     * The {@code algorithm} field name represented as a string value.
     */
    private static final String ALGORITHM_FIELD = "algorithm";

    /**
     * The {@code mode} field name represented as a string value.
     */
    private static final String MODE_FIELD = "mode";

    /**
     * The {@code padding} field name represented as a string value.
     */
    private static final String PADDING_FIELD = "padding";

    /**
     * The encryption algorithm for this transformation, not null.
     */
    @NotNull
    private CipherAlgorithm algorithm;

    /**
     * The operational mode for this transformation, may be null. If {@code null} then any configured {@link #padding}
     * is ignored.
     */
    private CipherMode mode;

    /**
     * The padding mode for this transformation, may be null. If {@code null} then any configured {@link #mode} is
     * ignored.
     */
    private CipherPadding padding;


    /**
     * Constructs a new {@code CipherTransformation} using the defaults of {@link CipherAlgorithm#AES}, {@link
     * CipherMode#GCM}, and {@link CipherPadding#NONE}.
     */
    public CipherTransformation() {
        this(CipherAlgorithm.AES);
    }

    /**
     * Constructs a new {@code CipherTransformation} with the specified algorithm. The operational mode defaults to
     * {@link CipherMode#GCM} and the padding mode defaults to {@link CipherPadding#NONE}.
     *
     * @param algorithm
     *         the encryption algorithm, not null
     * @throws IllegalArgumentException
     *         if the {@code algorithm} parameter is {@code null}
     */
    public CipherTransformation(@NotNull final CipherAlgorithm algorithm) {
        this(algorithm, CipherMode.GCM);
    }

    /**
     * Constructs a new {@code CipherTransformation} with the specified algorithm and operational mode. The padding mode
     * defaults to {@link CipherPadding#NONE}.
     *
     * @param algorithm
     *         the encryption algorithm, not null
     * @param mode
     *         the operational mode, may be null
     * @throws IllegalArgumentException
     *         if the {@code algorithm} parameter is {@code null}
     */
    public CipherTransformation(@NotNull final CipherAlgorithm algorithm, final CipherMode mode) {
        this(algorithm, mode, CipherPadding.NONE);
    }

    /**
     * Constructs a new {@code CipherTransformation} with the specified algorithm, operational mode, and padding.
     *
     * @param algorithm
     *         the encryption algorithm, not null
     * @param mode
     *         the operational mode, may be null
     * @param padding
     *         the padding mode, may be null
     * @throws IllegalArgumentException
     *         if the {@code algorithm} parameter is {@code null}
     */
    public CipherTransformation(@NotNull final CipherAlgorithm algorithm, final CipherMode mode,
                                final CipherPadding padding) {
        if (algorithm == null) {
            throw new IllegalArgumentException(ALGORITHM_FIELD);
        }

        this.algorithm = algorithm;
        this.mode = mode;
        this.padding = padding;
    }

    /**
     * Gets the encryption algorithm currently configured.
     *
     * @return the current encryption algorithm, not null
     * @see CipherAlgorithm
     */
    public CipherAlgorithm getAlgorithm() {
        return algorithm;
    }

    /**
     * Sets the encryption algorithm to be used for the transformation.
     *
     * @param algorithm
     *         the encryption algorithm, not null
     * @see CipherAlgorithm
     */
    public void setAlgorithm(@NotNull final CipherAlgorithm algorithm) {
        if (algorithm == null) {
            throw new IllegalArgumentException(ALGORITHM_FIELD);
        }

        this.algorithm = algorithm;
    }

    /**
     * Gets the operational mode used by the encryption algorithm.
     *
     * @return the current operational mode, may be null
     * @see CipherMode
     */
    public CipherMode getMode() {
        return mode;
    }

    /**
     * Sets the operational mode to be used by the encryption algorithm. If {@code null} is supplied for the operational
     * mode then any configured {@code padding} will also be ignored.
     *
     * @param mode
     *         the operational mode, may be null
     * @see CipherMode
     * @see #getPadding()
     */
    public void setMode(final CipherMode mode) {
        this.mode = mode;
    }

    /**
     * Gets the padding mode used by the encryption algorithm.
     *
     * @return the current padding mode, may be null
     * @see CipherPadding
     */
    public CipherPadding getPadding() {
        return padding;
    }

    /**
     * Sets the padding mode to be used by the encryption algorithm. If {@code null} is supplied for the padding then
     * any configured {@code mode} will also be ignored.
     *
     * @param padding
     *         the padding mode, may be null
     * @see CipherPadding
     * @see #getMode()
     */
    public void setPadding(final CipherPadding padding) {
        this.padding = padding;
    }

    /**
     * Generates a string representation of the algorithm name, mode, and padding in the format required by the {@link
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
                .append(ALGORITHM_FIELD, algorithm)
                .append(MODE_FIELD, mode)
                .append(PADDING_FIELD, padding)
                .toString();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Cipher instance() {
        try {
            return Cipher.getInstance(toCipherTransform());
        } catch (NoSuchPaddingException | NoSuchAlgorithmException ex) {
            throw new CryptographyException(ex);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Cipher instance(@NotNull final String provider) {
        try {
            return Cipher.getInstance(toCipherTransform(), provider);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | NoSuchProviderException ex) {
            throw new CryptographyException(ex);
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Cipher instance(@NotNull final Provider provider) {
        try {
            return Cipher.getInstance(toCipherTransform(), provider);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException ex) {
            throw new CryptographyException(ex);
        }
    }
}
