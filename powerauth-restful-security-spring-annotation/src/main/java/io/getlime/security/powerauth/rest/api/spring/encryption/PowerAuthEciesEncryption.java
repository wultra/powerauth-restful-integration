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
package io.getlime.security.powerauth.rest.api.spring.encryption;

import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesDecryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;

/**
 * Class used for storing data used during ECIES decryption and encryption. A reference to an initialized ECIES decryptor
 * is also stored so that response can be encrypted using same decryptor as used for request decryption.
 * <p>
 * Use the T parameter to specify the type of request object to be decrypted.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthEciesEncryption {

    private final EciesEncryptionContext context;
    private EciesDecryptor eciesDecryptor;
    private EciesEncryptor eciesEncryptor;
    private byte[] encryptedRequest;
    private byte[] decryptedRequest;
    private byte[] associatedData;
    private Object requestObject;

    /**
     * Initialize ECIES encryption object from either encryption or signature HTTP header.
     *
     * @param context PowerAuth encryption context derived from either encryption or signature HTTP header.
     */
    public PowerAuthEciesEncryption(EciesEncryptionContext context) {
        this.context = context;
    }

    /**
     * Get ECIES encryption context.
     * @return ECIES encryption context.
     */
    public EciesEncryptionContext getContext() {
        return context;
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
     * Get ECIES encryptor.
     * @return eciesEncryptor ECIES encryptor.
     */
    public EciesEncryptor getEciesEncryptor() {
        return eciesEncryptor;
    }

    /**
     * Set ECIES encryptor.
     * @param eciesEncryptor ECIES encryptor.
     */
    public void setEciesEncryptor(EciesEncryptor eciesEncryptor) {
        this.eciesEncryptor = eciesEncryptor;
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

    /**
     * Get ECIES data associated with request and response.
     * @return ECIES data associated with request and response.
     */
    public byte[] getAssociatedData() {
        return associatedData;
    }

    /**
     * Set ECIES data associated with request and response.
     * @param associatedData ECIES data associated with request and response.
     */
    public void setAssociatedData(byte[] associatedData) {
        this.associatedData = associatedData;
    }

    /**
     * Get decrypted request object.
     * @return Decrypted request object.
     */
    public Object getRequestObject() {
        return requestObject;
    }

    /**
     * Set decrypted request object.
     * @param requestObject Decrypted request object.
     */
    public void setRequestObject(Object requestObject) {
        this.requestObject = requestObject;
    }

}
