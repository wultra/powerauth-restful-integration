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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.crypto.lib.encryptor.NonPersonalizedEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.NonPersonalizedEncryptedMessage;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.rest.api.model.entity.NonPersonalizedEncryptedPayloadModel;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.Base64;

/**
 * Non-personalized encryptor class.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class PowerAuthNonPersonalizedEncryptor {

    private final NonPersonalizedEncryptor encryptor;

    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * Constructor with all mandatory parameters.
     *
     * @param applicationKeyBase64 Application key.
     * @param sessionKeyBytesBase64 Session key.
     * @param sessionIndexBase64 Session index.
     * @param ephemeralPublicKeyBase64 Ephemeral public key.
     */
    public PowerAuthNonPersonalizedEncryptor(String applicationKeyBase64, String sessionKeyBytesBase64, String sessionIndexBase64, String ephemeralPublicKeyBase64) {
        final byte[] applicationKey = Base64.getDecoder().decode(applicationKeyBase64);
        final byte[] sessionIndex = Base64.getDecoder().decode(sessionIndexBase64);
        final byte[] sessionKeyBytes = Base64.getDecoder().decode(sessionKeyBytesBase64);
        final byte[] ephemeralKeyBytes = Base64.getDecoder().decode(ephemeralPublicKeyBase64);
        this.encryptor = new NonPersonalizedEncryptor(applicationKey, sessionKeyBytes, sessionIndex, ephemeralKeyBytes);
    }

    /**
     * Encrypt object.
     *
     * @param object Object to be encrypted.
     * @return Encrypted object.
     * @throws JsonProcessingException In case the resulting object cannot be encoded as JSON.
     * @throws GenericCryptoException In case of a cryptography error.
     * @throws CryptoProviderException In case of a cryptographic provider error.
     * @throws InvalidKeyException In case the key provided for encryption is invalid.
     */
    public ObjectResponse<NonPersonalizedEncryptedPayloadModel> encrypt(Object object) throws JsonProcessingException, GenericCryptoException, CryptoProviderException, InvalidKeyException {
        if (object == null) {
            return null;
        }
        final byte[] originalData = mapper.writeValueAsBytes(object);
        return this.encrypt(originalData);
    }

    /**
     * Encrypt data.
     *
     * @param originalData Bytes to be encrypted.
     * @return Encrypted object.
     * @throws GenericCryptoException In case of a cryptography error.
     * @throws CryptoProviderException In case of a cryptographic provider error.
     * @throws InvalidKeyException In case the key provided for encryption is invalid.
     */
    public ObjectResponse<NonPersonalizedEncryptedPayloadModel> encrypt(byte[] originalData) throws GenericCryptoException, CryptoProviderException, InvalidKeyException {

        if (originalData == null) {
            return null;
        }

        final NonPersonalizedEncryptedMessage message = encryptor.encrypt(originalData);

        if (message == null) { // this will happen only in case of an unlikely randomness error, or if keys are corrupted
            return null;
        }

        final NonPersonalizedEncryptedPayloadModel responseObject = new NonPersonalizedEncryptedPayloadModel();
        responseObject.setApplicationKey(Base64.getEncoder().encodeToString(message.getApplicationKey()));
        responseObject.setEphemeralPublicKey(Base64.getEncoder().encodeToString(message.getEphemeralPublicKey()));
        responseObject.setSessionIndex(Base64.getEncoder().encodeToString(message.getSessionIndex()));
        responseObject.setAdHocIndex(Base64.getEncoder().encodeToString(message.getAdHocIndex()));
        responseObject.setMacIndex(Base64.getEncoder().encodeToString(message.getMacIndex()));
        responseObject.setNonce(Base64.getEncoder().encodeToString(message.getNonce()));
        responseObject.setMac(Base64.getEncoder().encodeToString(message.getMac()));
        responseObject.setEncryptedData(Base64.getEncoder().encodeToString(message.getEncryptedData()));

        return new ObjectResponse<>(responseObject);
    }

    /**
     * Decrypt an object.
     *
     * @param request Object with encrypted payload.
     * @return Decrypted bytes.
     * @throws GenericCryptoException In case of a cryptography error.
     * @throws CryptoProviderException In case of a cryptographic provider error.
     * @throws InvalidKeyException In case the key provided for encryption is invalid.
     */
    public byte[] decrypt(ObjectRequest<NonPersonalizedEncryptedPayloadModel> request) throws GenericCryptoException, CryptoProviderException, InvalidKeyException {

        if (request == null) {
            return null;
        }

        final NonPersonalizedEncryptedPayloadModel requestObject = request.getRequestObject();

        if (requestObject == null) {
            return null;
        }

        final NonPersonalizedEncryptedMessage message = new NonPersonalizedEncryptedMessage();
        message.setApplicationKey(Base64.getDecoder().decode(requestObject.getApplicationKey()));
        message.setEphemeralPublicKey(Base64.getDecoder().decode(requestObject.getEphemeralPublicKey()));
        message.setSessionIndex(Base64.getDecoder().decode(requestObject.getSessionIndex()));
        message.setAdHocIndex(Base64.getDecoder().decode(requestObject.getAdHocIndex()));
        message.setMacIndex(Base64.getDecoder().decode(requestObject.getMacIndex()));
        message.setNonce(Base64.getDecoder().decode(requestObject.getNonce()));
        message.setMac(Base64.getDecoder().decode(requestObject.getMac()));
        message.setEncryptedData(Base64.getDecoder().decode(requestObject.getEncryptedData()));

        return encryptor.decrypt(message);
    }

    /**
     * Decrypt data and serialize object.
     *
     * @param request Request with encrypted data.
     * @param resultClass Result deserialized class.
     * @param <T> Specific type of the result class.
     * @return Decrypted object of a provided type T.
     * @throws IOException In case the JSON deserialization fails.
     * @throws GenericCryptoException In case of a cryptography error.
     * @throws CryptoProviderException In case of a cryptographic provider error.
     * @throws InvalidKeyException In case the key provided for encryption is invalid.
     */
    public <T> T decrypt(ObjectRequest<NonPersonalizedEncryptedPayloadModel> request, Class<T> resultClass) throws IOException, GenericCryptoException, CryptoProviderException, InvalidKeyException {
        final byte[] result = this.decrypt(request);
        if (result == null) {
            return null;
        }
        return mapper.readValue(result, resultClass);
    }

}
