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
package io.getlime.security.powerauth.rest.api.model.request.v2;

/**
 * Request object for /pa/activation/create end-point.
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
public class ActivationCreateRequest {

    private String activationIdShort;
    private String activationNonce;
    private String ephemeralPublicKey;
    private String encryptedDevicePublicKey;
    private String activationName;
    private String extras;
    private String applicationKey;
    private String applicationSignature;

    /**
     * Get activation ID short.
     * @return Activation ID short.
     */
    public String getActivationIdShort() {
        return activationIdShort;
    }

    /**
     * Set activation ID short.
     * @param activationIdShort Activation ID short.
     */
    public void setActivationIdShort(String activationIdShort) {
        this.activationIdShort = activationIdShort;
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
     * Get the ephemeral public key.
     * @return Ephemeral public key.
     */
    public String getEphemeralPublicKey() {
        return ephemeralPublicKey;
    }

    /**
     * Set the ephemeral public key.
     * @param ephemeralPublicKey Ephemeral public key.
     */
    public void setEphemeralPublicKey(String ephemeralPublicKey) {
        this.ephemeralPublicKey = ephemeralPublicKey;
    }

    /**
     * Get encrypted device public key.
     * @return cDevicePublicKey
     */
    public String getEncryptedDevicePublicKey() {
        return encryptedDevicePublicKey;
    }

    /**
     * Set encrypted device public key.
     * @param encryptedDevicePublicKey Encrypted device public key.
     */
    public void setEncryptedDevicePublicKey(String encryptedDevicePublicKey) {
        this.encryptedDevicePublicKey = encryptedDevicePublicKey;
    }

    /**
     * Get activation name.
     * @return Activation name.
     */
    public String getActivationName() {
        return activationName;
    }

    /**
     * Set activation name.
     * @param activationName Activation name.
     */
    public void setActivationName(String activationName) {
        this.activationName = activationName;
    }

    /**
     * Get extra parameter.
     * @return Extra parameter.
     */
    public String getExtras() {
        return extras;
    }

    /**
     * Set extra parameter.
     * @param extras Extra parameter.
     */
    public void setExtras(String extras) {
        this.extras = extras;
    }

    /**
     * Get application key.
     * @return Application key.
     */
    public String getApplicationKey() {
        return applicationKey;
    }

    /**
     * Set application key.
     * @param applicationKey Application key.
     */
    public void setApplicationKey(String applicationKey) {
        this.applicationKey = applicationKey;
    }

    /**
     * Get application signature.
     * @return Application signature.
     */
    public String getApplicationSignature() {
        return applicationSignature;
    }

    /**
     * Set application signature.
     * @param applicationSignature Application signature.
     */
    public void setApplicationSignature(String applicationSignature) {
        this.applicationSignature = applicationSignature;
    }

}
