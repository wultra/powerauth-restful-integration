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
package io.getlime.security.powerauth.rest.api.model.response;

/**
 * Response object for endpoints returning data encrypted by ECIES.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class EciesEncryptedResponse {

    private String ephemeralPublicKey;
    private String encryptedData;
    private String mac;
    private String nonce;
    private Long timestamp;

    /**
     * Default constructor.
     */
    public EciesEncryptedResponse() {
    }

    /**
     * Constructor with Base64 encoded encrypted data and MAC of key and data.
     * @param encryptedData Encrypted data.
     * @param mac MAC of key and data.
     * @param ephemeralPublicKey Ephemeral public key.
     * @param nonce ECIES nonce.
     * @param timestamp Unix timestamp in milliseconds.
     */
    public EciesEncryptedResponse(String encryptedData, String mac, String ephemeralPublicKey, String nonce, Long timestamp) {
        this.encryptedData = encryptedData;
        this.mac = mac;
        this.ephemeralPublicKey = ephemeralPublicKey;
        this.nonce = nonce;
        this.timestamp = timestamp;
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
     * Get Base64 encoded encrypted data payload.
     * @return Encrypted data.
     */
    public String getEncryptedData() {
        return encryptedData;
    }

    /**
     * Set Base64 encoded encrypted data payload.
     * @param encryptedData Encrypted data.
     */
    public void setEncryptedData(String encryptedData) {
        this.encryptedData = encryptedData;
    }

    /**
     * Get Base64 encoded MAC signature of the response.
     * @return MAC of the response.
     */
    public String getMac() {
        return mac;
    }

    /**
     * Set Base64 encoded MAC signature of the response.
     * @param mac MAC of the response.
     */
    public void setMac(String mac) {
        this.mac = mac;
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
     * Get response timestamp as unix timestamp in milliseconds.
     * @return Response timestamp.
     */
    public Long getTimestamp() {
        return timestamp;
    }

    /**
     * Set response timestamp as unix timestamp in milliseconds.
     * @param timestamp Response timestamp.
     */
    public void setTimestamp(Long timestamp) {
        this.timestamp = timestamp;
    }
}
