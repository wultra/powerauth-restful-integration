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

package io.getlime.security.powerauth.rest.api.base.encryption;

import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesDecryptor;
import io.getlime.security.powerauth.http.PowerAuthEncryptionHttpHeader;

/**
 * Class used for storing data used during ECIES decryption and encryption. A reference to an initialized ECIES decryptor
 * is also stored so that response can be encrypted using same decryptor as used for request decryption.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthEciesEncryption {

    private String applicationKey;
    private String activationId;
    private String version;
    private PowerAuthEncryptionHttpHeader httpHeader;
    private EciesDecryptor eciesDecryptor;
    private byte[] encryptedRequest;
    private byte[] decryptedRequest;

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
     * Get activation ID.
     * @return Activation ID.
     */
    public String getActivationId() {
        return activationId;
    }

    /**
     * Set activation ID.
     * @param activationId Activation ID.
     */
    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    /**
     * Get PowerAuth protocol version.
     * @return PowerAuth protocol version.
     */
    public String getVersion() {
        return version;
    }

    /**
     * Set PowerAuth protocol version.
     * @param version PowerAuth protocol version.
     */
    public void setVersion(String version) {
        this.version = version;
    }

    /**
     * Get PowerAuth encryption HTTP header.
     * @return PowerAuth encryption HTTP header.
     */
    public PowerAuthEncryptionHttpHeader getHttpHeader() {
        return httpHeader;
    }

    /**
     * Set PowerAuth encryption HTTP header.
     * @param httpHeader PowerAuth encryption HTTP header.
     */
    public void setHttpHeader(PowerAuthEncryptionHttpHeader httpHeader) {
        this.httpHeader = httpHeader;
    }

    /**
     * Get ECIES decryptor.
     * @return ECIES decryptor.
     */
    public EciesDecryptor getEciesDecryptor() {
        return eciesDecryptor;
    }

    /**
     * Set ECIES decryptor.
     * @param eciesDecryptor ECIES decryptor.
     */
    public void setEciesDecryptor(EciesDecryptor eciesDecryptor) {
        this.eciesDecryptor = eciesDecryptor;
    }

    /**
     * Get encrypted request data.
     * @return Encrypted request data.
     */
    public byte[] getEncryptedRequest() {
        return encryptedRequest;
    }

    /**
     * Set encrypted request data.
     * @param encryptedRequest Encrypted request data.
     */
    public void setEncryptedRequest(byte[] encryptedRequest) {
        this.encryptedRequest = encryptedRequest;
    }

    /**
     * Get decrypted request data.
     * @return Decrypted request data.
     */
    public byte[] getDecryptedRequest() {
        return decryptedRequest;
    }

    /**
     * Set decrypted request data.
     * @param decryptedRequest Decrypted request data.
     */
    public void setDecryptedRequest(byte[] decryptedRequest) {
        this.decryptedRequest = decryptedRequest;
    }
}
