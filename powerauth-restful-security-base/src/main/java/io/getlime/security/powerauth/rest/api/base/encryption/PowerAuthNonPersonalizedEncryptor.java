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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.crypto.lib.encryptor.NonPersonalizedEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.NonPersonalizedEncryptedMessage;
import io.getlime.security.powerauth.rest.api.model.entity.NonPersonalizedEncryptedPayloadModel;

import java.io.IOException;

/**
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class PowerAuthNonPersonalizedEncryptor {

    private NonPersonalizedEncryptor encryptor;

    private ObjectMapper mapper = new ObjectMapper();

    public PowerAuthNonPersonalizedEncryptor(String applicationKeyBase64, String sessionKeyBytesBase64, String sessionIndexBase64, String ephemeralPublicKeyBase64) {
        byte[] applicationKey = BaseEncoding.base64().decode(applicationKeyBase64);
        byte[] sessionIndex = BaseEncoding.base64().decode(sessionIndexBase64);
        byte[] sessionKeyBytes = BaseEncoding.base64().decode(sessionKeyBytesBase64);
        byte[] ephemeralKeyBytes = BaseEncoding.base64().decode(ephemeralPublicKeyBase64);
        this.encryptor = new NonPersonalizedEncryptor(applicationKey, sessionKeyBytes, sessionIndex, ephemeralKeyBytes);
    }

    public ObjectResponse<NonPersonalizedEncryptedPayloadModel> encrypt(Object object) throws JsonProcessingException {
        if (object == null) {
            return null;
        }
        byte[] originalData = mapper.writeValueAsBytes(object);
        return this.encrypt(originalData);
    }

    public ObjectResponse<NonPersonalizedEncryptedPayloadModel> encrypt(byte[] originalData) {

        if (originalData == null) {
            return null;
        }

        NonPersonalizedEncryptedMessage message = encryptor.encrypt(originalData);

        if (message == null) { // this will happen only in case of an unlikely randomness error, or if keys are corrupted
            return null;
        }

        NonPersonalizedEncryptedPayloadModel responseObject = new NonPersonalizedEncryptedPayloadModel();
        responseObject.setApplicationKey(BaseEncoding.base64().encode(message.getApplicationKey()));
        responseObject.setEphemeralPublicKey(BaseEncoding.base64().encode(message.getEphemeralPublicKey()));
        responseObject.setSessionIndex(BaseEncoding.base64().encode(message.getSessionIndex()));
        responseObject.setAdHocIndex(BaseEncoding.base64().encode(message.getAdHocIndex()));
        responseObject.setMacIndex(BaseEncoding.base64().encode(message.getMacIndex()));
        responseObject.setNonce(BaseEncoding.base64().encode(message.getNonce()));
        responseObject.setMac(BaseEncoding.base64().encode(message.getMac()));
        responseObject.setEncryptedData(BaseEncoding.base64().encode(message.getEncryptedData()));

        return new ObjectResponse<>(responseObject);
    }

    public byte[] decrypt(ObjectRequest<NonPersonalizedEncryptedPayloadModel> request) {

        if (request == null) {
            return null;
        }

        NonPersonalizedEncryptedPayloadModel requestObject = request.getRequestObject();

        if (requestObject == null) {
            return null;
        }

        NonPersonalizedEncryptedMessage message = new NonPersonalizedEncryptedMessage();
        message.setApplicationKey(BaseEncoding.base64().decode(requestObject.getApplicationKey()));
        message.setEphemeralPublicKey(BaseEncoding.base64().decode(requestObject.getEphemeralPublicKey()));
        message.setSessionIndex(BaseEncoding.base64().decode(requestObject.getSessionIndex()));
        message.setAdHocIndex(BaseEncoding.base64().decode(requestObject.getAdHocIndex()));
        message.setMacIndex(BaseEncoding.base64().decode(requestObject.getMacIndex()));
        message.setNonce(BaseEncoding.base64().decode(requestObject.getNonce()));
        message.setMac(BaseEncoding.base64().decode(requestObject.getMac()));
        message.setEncryptedData(BaseEncoding.base64().decode(requestObject.getEncryptedData()));

        return encryptor.decrypt(message);
    }

    public <T> T decrypt(ObjectRequest<NonPersonalizedEncryptedPayloadModel> request, Class<T> resultClass) throws IOException {
        byte[] result = this.decrypt(request);
        if (result == null) {
            return null;
        }
        return mapper.readValue(result, resultClass);
    }

}
