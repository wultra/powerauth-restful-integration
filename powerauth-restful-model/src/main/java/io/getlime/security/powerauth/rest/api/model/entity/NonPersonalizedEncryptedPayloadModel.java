/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2018 Wultra s.r.o.
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
package io.getlime.security.powerauth.rest.api.model.entity;

/**
 * Class representing a payload encrypted using non-personalized end-to-end encryption.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class NonPersonalizedEncryptedPayloadModel {

    private String applicationKey;
    private String sessionIndex;
    private String adHocIndex;
    private String macIndex;
    private String nonce;
    private String ephemeralPublicKey;
    private String mac;
    private String encryptedData;

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
     * Get session index.
     * @return Session index.
     */
    public String getSessionIndex() {
        return sessionIndex;
    }

    /**
     * Set session index.
     * @param sessionIndex Session index.
     */
    public void setSessionIndex(String sessionIndex) {
        this.sessionIndex = sessionIndex;
    }

    /**
     * Get ad-hoc index.
     * @return Ad-hoc index.
     */
    public String getAdHocIndex() {
        return adHocIndex;
    }

    /**
     * Set ad-hoc index.
     * @param adHocIndex Ad-hoc index.
     */
    public void setAdHocIndex(String adHocIndex) {
        this.adHocIndex = adHocIndex;
    }

    /**
     * Get MAC index.
     * @return MAC index.
     */
    public String getMacIndex() {
        return macIndex;
    }

    /**
     * Set MAC index.
     * @param macIndex MAC index.
     */
    public void setMacIndex(String macIndex) {
        this.macIndex = macIndex;
    }

    /**
     * Get nonce.
     * @return Nonce.
     */
    public String getNonce() {
        return nonce;
    }

    /**
     * Set nonce.
     * @param nonce Nonce.
     */
    public void setNonce(String nonce) {
        this.nonce = nonce;
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
     * Get MAC.
     * @return MAC.
     */
    public String getMac() {
        return mac;
    }

    /**
     * Set MAC.
     * @param mac MAC.
     */
    public void setMac(String mac) {
        this.mac = mac;
    }

    /**
     * Get encrypted data.
     * @return Encrypted data.
     */
    public String getEncryptedData() {
        return encryptedData;
    }

    /**
     * Set encrypted data.
     * @param encryptedData Encrypted data.
     */
    public void setEncryptedData(String encryptedData) {
        this.encryptedData = encryptedData;
    }
}
