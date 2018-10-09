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

package io.getlime.security.powerauth.rest.api.model.request.v3;

/**
 * Request object for the /pa/v3/token endpoint, that enables fetching token for simple authentication.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class TokenCreateRequest {

    private String ephemeralKey;
    private String encryptedData;
    private String mac;

    /**
     * Get Base64 encoded ephemeral public key.
     * @return Ephemeral public key.
     */
    public String getEphemeralKey() {
        return ephemeralKey;
    }

    /**
     * Set Base64 encoded ephemeral public key.
     * @param ephemeralKey Ephemeral public key.
     */
    public void setEphemeralKey(String ephemeralKey) {
        this.ephemeralKey = ephemeralKey;
    }

    /**
     * Get Base64 encoded encrypted data.
     * @return Encrypted data.
     */
    public String getEncryptedData() {
        return encryptedData;
    }

    /**
     * Set Base64 encoded encrypted data.
     * @param encryptedData Encrypted data.
     */
    public void setEncryptedData(String encryptedData) {
        this.encryptedData = encryptedData;
    }

    /**
     * Get Base64 encoded MAC of key and data.
     * @return MAC of key and data.
     */
    public String getMac() {
        return mac;
    }

    /**
     * Set Base64 encoded MAC of key and data.
     * @param mac MAC of key and data.
     */
    public void setMac(String mac) {
        this.mac = mac;
    }
}
