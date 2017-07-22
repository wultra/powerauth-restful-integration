/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2017 Lime - HighTech Solutions s.r.o.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package io.getlime.security.powerauth.rest.api.model.response;

import java.util.Map;

/**
 * Response object for /pa/activation/create end-point.
 *
 * @author Petr Dvorak
 *
 */
public class ActivationCreateResponse {

    private String activationId;
    private String activationNonce;
    private String ephemeralPublicKey;
    private String encryptedServerPublicKey;
    private String encryptedServerPublicKeySignature;
    private Map<String, Object> customAttributes;

    /**
     * Get activation ID
     * @return Activation ID
     */
    public String getActivationId() {
        return activationId;
    }

    /**
     * Set activation ID
     * @param activationId Activation ID
     */
    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    /**
     * Get activation nonce.
     * @return Activation nonce.
     */
    public String getActivationNonce() {
        return activationNonce;
    }

    /**
     * Set activation nonce.
     * @param activationNonce Activation nonce.
     */
    public void setActivationNonce(String activationNonce) {
        this.activationNonce = activationNonce;
    }

    /**
     * Get ephemeral public key.
     * @return Ephemeral public key.
     */
    public String getEphemeralPublicKey() {
        return ephemeralPublicKey;
    }

    /**
     * Set ephemeral public key.
     * @param ephemeralPublicKey Ephemeral public key.
     */
    public void setEphemeralPublicKey(String ephemeralPublicKey) {
        this.ephemeralPublicKey = ephemeralPublicKey;
    }

    /**
     * Get encrypted server public key.
     * @return Encrypted server public key.
     */
    public String getEncryptedServerPublicKey() {
        return encryptedServerPublicKey;
    }

    /**
     * Set encrypted server public key.
     * @param encryptedServerPublicKey Encrypted server public key.
     */
    public void setEncryptedServerPublicKey(String encryptedServerPublicKey) {
        this.encryptedServerPublicKey = encryptedServerPublicKey;
    }

    /**
     * Get server data signature.
     * @return Server data signature.
     */
    public String getEncryptedServerPublicKeySignature() {
        return encryptedServerPublicKeySignature;
    }

    /**
     * Set server data signature.
     * @param encryptedServerPublicKeySignature Server data signature.
     */
    public void setEncryptedServerPublicKeySignature(String encryptedServerPublicKeySignature) {
        this.encryptedServerPublicKeySignature = encryptedServerPublicKeySignature;
    }

    /**
     * Custom attributes for the response.
     * @return Custom response attributes.
     */
    public Map<String, Object> getCustomAttributes() {
        return customAttributes;
    }

    /**
     * Custom attributes for the response.
     * @param customAttributes Custom response attributes.
     */
    public void setCustomAttributes(Map<String, Object> customAttributes) {
        this.customAttributes = customAttributes;
    }

}
