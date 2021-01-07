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
package io.getlime.security.powerauth.app.rest.api.javaee.controller.v2;

import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.crypto.lib.model.exception.CryptoProviderException;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.rest.api.base.encryption.PowerAuthNonPersonalizedEncryptor;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthEncryptionException;
import io.getlime.security.powerauth.rest.api.jaxrs.encryption.EncryptorFactory;
import io.getlime.security.powerauth.rest.api.model.entity.NonPersonalizedEncryptedPayloadModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;

/**
 * Sample end-point demonstrating how to receive and send encrypted data.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>2.0</li>
 *     <li>2.1</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Produces(MediaType.APPLICATION_JSON)
public class EncryptedDataExchangeController {

    private static final Logger logger = LoggerFactory.getLogger(EncryptedDataExchangeController.class);

    @Context
    private HttpServletRequest httpServletRequest;

    @Inject
    private EncryptorFactory encryptorFactory;

    /**
     * Sample encrypted data exchange.
     *
     * @param request Encrypted request.
     * @return Encrypted response.
     * @throws PowerAuthEncryptionException In case encryption or decryption fails.
     */
    @POST
    @Path("exchange")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public ObjectResponse<NonPersonalizedEncryptedPayloadModel> exchange(ObjectRequest<NonPersonalizedEncryptedPayloadModel> request) throws PowerAuthEncryptionException {
        if (request == null) {
            logger.warn("Invalid request in exchange method");
            throw new PowerAuthEncryptionException();
        }

        // Prepare an encryptor
        PowerAuthNonPersonalizedEncryptor encryptor;
        try {
             encryptor = encryptorFactory.buildNonPersonalizedEncryptor(request);
        } catch (RemoteException ex) {
            logger.warn("Remote communication failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthEncryptionException();
        }

        // Decrypt the request object
        byte[] requestDataBytes;
        try {
            requestDataBytes = encryptor.decrypt(request);
        } catch (GenericCryptoException | CryptoProviderException | InvalidKeyException ex) {
            logger.warn("Encryption failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthEncryptionException();
        }

        if (requestDataBytes == null) {
            logger.warn("Invalid request data in exchange method");
            throw new PowerAuthEncryptionException();
        }

        String requestData = new String(requestDataBytes);

        // Return a slightly different String containing original data in response
        String responseData = "Server successfully decrypted data: " + requestData;

        // Encrypt response data
        ObjectResponse<NonPersonalizedEncryptedPayloadModel> encryptedResponse;
        try {
            encryptedResponse = encryptor.encrypt(responseData.getBytes());
        } catch (GenericCryptoException | CryptoProviderException | InvalidKeyException ex) {
            logger.warn("Encryption failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthEncryptionException();
        }

        return encryptedResponse;
    }

}
