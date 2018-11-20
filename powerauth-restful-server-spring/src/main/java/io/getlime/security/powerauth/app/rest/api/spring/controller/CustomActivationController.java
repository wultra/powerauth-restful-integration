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
import io.getlime.powerauth.soap.v2.CreateActivationResponse;
import io.getlime.security.powerauth.app.rest.api.spring.provider.DefaultCustomActivationProvider;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.provider.exception.CryptoProviderException;
import io.getlime.security.powerauth.rest.api.base.encryption.PowerAuthEciesEncryption;
import io.getlime.security.powerauth.rest.api.base.encryption.PowerAuthNonPersonalizedEncryptor;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthActivationException;
import io.getlime.security.powerauth.rest.api.base.provider.PowerAuthCustomActivationProvider;
import io.getlime.security.powerauth.rest.api.model.entity.ActivationType;
import io.getlime.security.powerauth.rest.api.model.entity.NonPersonalizedEncryptedPayloadModel;
import io.getlime.security.powerauth.rest.api.model.request.v2.ActivationCreateCustomRequest;
import io.getlime.security.powerauth.rest.api.model.request.v2.ActivationCreateRequest;
import io.getlime.security.powerauth.rest.api.model.request.v3.ActivationLayer1Request;
import io.getlime.security.powerauth.rest.api.model.response.v2.ActivationCreateResponse;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationLayer1Response;
import io.getlime.security.powerauth.rest.api.spring.annotation.EncryptedRequestBody;
import io.getlime.security.powerauth.rest.api.spring.annotation.PowerAuthEncryption;
import io.getlime.security.powerauth.rest.api.spring.encryption.EncryptorFactory;
import io.getlime.security.powerauth.rest.api.spring.service.v3.ActivationService;
import io.getlime.security.powerauth.soap.spring.client.PowerAuthServiceClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.Map;

/**
 * Example controller for a custom activation implementation.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Controller
@RequestMapping(value = "/pa/activation/direct")
public class CustomActivationController {

    private PowerAuthServiceClient powerAuthClient;

    private EncryptorFactory encryptorFactory;

    private PowerAuthCustomActivationProvider activationProvider;

    private ActivationService activationService;

    @Autowired
    public void setPowerAuthClient(PowerAuthServiceClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @Autowired
    public void setEncryptorFactory(EncryptorFactory encryptorFactory) {
        this.encryptorFactory = encryptorFactory;
    }

    @Autowired(required = false)
    public void setPowerAuthActivationProvider(PowerAuthCustomActivationProvider activationProvider) {
        this.activationProvider = activationProvider;
    }

    @Autowired
    public void setActivationService(ActivationService activationService) {
        this.activationService = activationService;
    }

    /**
     * Sample custom activation implementation for version 2 of activations.
     *
     * <h5>PowerAuth protocol versions:</h5>
     * <ul>
     *     <li>2.0</li>
     *     <li>2.1</li>
     * </ul>
     *
     * @param encryptedRequest Activation request encrypted using non-personalised end-to-end encryption.
     * @return Encrypted activation response.
     * @throws PowerAuthActivationException In case custom activation fails.
     */
    @RequestMapping(value = "create", method = RequestMethod.POST)
    public @ResponseBody ObjectResponse<NonPersonalizedEncryptedPayloadModel> createActivationV2(
            @RequestBody ObjectRequest<NonPersonalizedEncryptedPayloadModel> encryptedRequest
    ) throws PowerAuthActivationException {
        try {

            // Check if there is any user provider to be autowired
            if (activationProvider == null) {
                throw new PowerAuthActivationException();
            }

            // Prepare an encryptor
            final PowerAuthNonPersonalizedEncryptor encryptor = encryptorFactory.buildNonPersonalizedEncryptor(encryptedRequest);
            if (encryptor == null) {
                throw new PowerAuthActivationException();
            }

            // Decrypt the request object
            ActivationCreateCustomRequest request = encryptor.decrypt(encryptedRequest, ActivationCreateCustomRequest.class);

            if (request == null) {
                throw new PowerAuthActivationException();
            }

            // Lookup user ID using a provided identity
            final Map<String, String> identity = request.getIdentity();
            String userId = activationProvider.lookupUserIdForAttributes(identity);

            // If no user was found or user ID is invalid, return error
            if (userId == null || userId.equals("") || userId.length() > 255) {
                throw new PowerAuthActivationException();
            }

            // Create activation for a looked up user and application related to the given application key
            ActivationCreateRequest acr = request.getPowerauth();
            CreateActivationResponse response = powerAuthClient.v2().createActivation(
                    acr.getApplicationKey(),
                    userId,
                    acr.getActivationIdShort(),
                    acr.getActivationName(),
                    acr.getActivationNonce(),
                    acr.getEphemeralPublicKey(),
                    acr.getEncryptedDevicePublicKey(),
                    acr.getExtras(),
                    acr.getApplicationSignature()
            );

            // Process custom attributes using a custom logic
            final Map<String, Object> customAttributes = request.getCustomAttributes();
            activationProvider.processCustomActivationAttributes(customAttributes, response.getActivationId(), userId, ActivationType.CUSTOM);

            // Prepare the created activation response data
            ActivationCreateResponse createResponse = new ActivationCreateResponse();
            createResponse.setActivationId(response.getActivationId());
            createResponse.setEphemeralPublicKey(response.getEphemeralPublicKey());
            createResponse.setActivationNonce(response.getActivationNonce());
            createResponse.setEncryptedServerPublicKey(response.getEncryptedServerPublicKey());
            createResponse.setEncryptedServerPublicKeySignature(response.getEncryptedServerPublicKeySignature());

            // Encrypt response object
            final ObjectResponse<NonPersonalizedEncryptedPayloadModel> powerAuthApiResponse = encryptor.encrypt(createResponse);

            // Check if activation should be committed instantly and if yes, perform commit
            if (activationProvider.shouldAutoCommitActivation(identity, customAttributes)) {
                powerAuthClient.commitActivation(response.getActivationId());
            }

            // Return response
            return powerAuthApiResponse;

        } catch (IOException | GenericCryptoException | CryptoProviderException | InvalidKeyException ex) {
            throw new PowerAuthActivationException();
        }

    }

    /**
     * Sample custom activation implementation for version 3 of activations. In version 3 the default implementation
     * can be reused by implementing a custom activation provider which handles the logic during the activation.
     *
     * See {@link DefaultCustomActivationProvider} and
     * {@link io.getlime.security.powerauth.rest.api.spring.service.v3.ActivationService}.
     *
     * <h5>PowerAuth protocol versions:</h5>
     * <ul>
     *     <li>3.0</li>
     * </ul>
     *
     * @param request Activation request encrypted using ECIES.
     * @param eciesEncryption ECIES encryption object.
     * @return ECIES encrypted activation response.
     * @throws PowerAuthActivationException In case custom activation fails.
     */
    @RequestMapping(value = "v3/create", method = RequestMethod.POST)
    @PowerAuthEncryption
    public @ResponseBody ActivationLayer1Response createActivationV3(@EncryptedRequestBody ActivationLayer1Request request,
                                                                     PowerAuthEciesEncryption eciesEncryption) throws PowerAuthActivationException {
        return activationService.createActivation(request, eciesEncryption);
    }

}
