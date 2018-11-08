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
package io.getlime.security.powerauth.app.rest.api.spring.controller;

import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.provider.exception.CryptoProviderException;
import io.getlime.security.powerauth.rest.api.base.encryption.PowerAuthNonPersonalizedEncryptor;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthEncryptionException;
import io.getlime.security.powerauth.rest.api.model.entity.NonPersonalizedEncryptedPayloadModel;
import io.getlime.security.powerauth.rest.api.spring.encryption.EncryptorFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import java.security.InvalidKeyException;

/**
 * Sample end-point demonstrating how to receive and send encrypted data.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@Controller
public class EncryptedDataExchangeController {

    private EncryptorFactory encryptorFactory;

    @Autowired
    public void setEncryptorFactory(EncryptorFactory encryptorFactory) {
        this.encryptorFactory = encryptorFactory;
    }


    @RequestMapping(value = "exchange", method = RequestMethod.POST)
    public @ResponseBody ObjectResponse<NonPersonalizedEncryptedPayloadModel> exchange(@RequestBody ObjectRequest<NonPersonalizedEncryptedPayloadModel> request) throws PowerAuthEncryptionException {
        if (request == null) {
            throw new PowerAuthEncryptionException();
        }

        // Prepare an encryptor
        final PowerAuthNonPersonalizedEncryptor encryptor = encryptorFactory.buildNonPersonalizedEncryptor(request);
        if (encryptor == null) {
            throw new PowerAuthEncryptionException();
        }

        // Decrypt the request object
        byte[] requestDataBytes;
        try {
            requestDataBytes = encryptor.decrypt(request);
        } catch (GenericCryptoException | CryptoProviderException | InvalidKeyException ex) {
            throw new PowerAuthEncryptionException();
        }

        String requestData = new String(requestDataBytes);

        // In response return a slightly different String containing original data
        String responseData = "Server successfully decrypted data: " + requestData;

        // Encrypt response data
        ObjectResponse<NonPersonalizedEncryptedPayloadModel> encryptedResponse;
        try {
            encryptedResponse = encryptor.encrypt(responseData.getBytes());
        } catch (GenericCryptoException | CryptoProviderException | InvalidKeyException ex) {
            throw new PowerAuthEncryptionException();
        }

        return encryptedResponse;
    }


}
