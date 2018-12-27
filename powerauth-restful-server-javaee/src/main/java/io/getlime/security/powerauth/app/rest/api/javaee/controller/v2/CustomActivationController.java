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
import io.getlime.powerauth.soap.v2.PowerAuthPortV2ServiceStub;
import io.getlime.security.powerauth.crypto.lib.model.exception.GenericCryptoException;
import io.getlime.security.powerauth.provider.exception.CryptoProviderException;
import io.getlime.security.powerauth.rest.api.base.encryption.PowerAuthNonPersonalizedEncryptor;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthActivationException;
import io.getlime.security.powerauth.rest.api.base.provider.CustomActivationProvider;
import io.getlime.security.powerauth.rest.api.jaxrs.encryption.EncryptorFactory;
import io.getlime.security.powerauth.rest.api.model.entity.ActivationType;
import io.getlime.security.powerauth.rest.api.model.entity.NonPersonalizedEncryptedPayloadModel;
import io.getlime.security.powerauth.rest.api.model.request.v2.ActivationCreateCustomRequest;
import io.getlime.security.powerauth.rest.api.model.request.v2.ActivationCreateRequest;
import io.getlime.security.powerauth.rest.api.model.response.v2.ActivationCreateResponse;
import io.getlime.security.powerauth.soap.axis.client.PowerAuthServiceClient;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.Map;

/**
 * Sample controller for a custom activation implementation.
 *
 * <h5>PowerAuth protocol versions:</h5>
 * <ul>
 *     <li>2.0</li>
 *     <li>2.1</li>
 * </ul>
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Path("/pa/activation/direct")
@Produces(MediaType.APPLICATION_JSON)
public class CustomActivationController {

    @Inject
    private PowerAuthServiceClient powerAuthClient;

    @Inject
    private EncryptorFactory encryptorFactory;

    @Inject
    private CustomActivationProvider activationProvider;

    /**
     * Sample custom activation implementation for version 2 of activations.
     *
     * @param object Encrypted activation request.
     * @return Encrypted activation response.
     * @throws PowerAuthActivationException In case activation fails.
     */
    @POST
    @Path("create")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public ObjectResponse<NonPersonalizedEncryptedPayloadModel> createActivationV2(ObjectRequest<NonPersonalizedEncryptedPayloadModel> object) throws PowerAuthActivationException {
        try {

            final PowerAuthNonPersonalizedEncryptor encryptor = encryptorFactory.buildNonPersonalizedEncryptor(object);

            if (encryptor == null) {
                throw new PowerAuthActivationException();
            }

            ActivationCreateCustomRequest request = encryptor.decrypt(object, ActivationCreateCustomRequest.class);

            if (request == null) {
                throw new PowerAuthActivationException();
            }

            final Map<String, String> identity = request.getIdentity();
            String userId = activationProvider.lookupUserIdForAttributes(identity);

            if (userId == null) {
                throw new PowerAuthActivationException();
            }

            ActivationCreateRequest acr = request.getPowerauth();
            PowerAuthPortV2ServiceStub.CreateActivationResponse response = powerAuthClient.v2().createActivation(
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

            final Map<String, Object> customAttributes = request.getCustomAttributes();
            activationProvider.processCustomActivationAttributes(customAttributes, response.getActivationId(), userId, ActivationType.CUSTOM);

            ActivationCreateResponse createResponse = new ActivationCreateResponse();
            createResponse.setActivationId(response.getActivationId());
            createResponse.setEphemeralPublicKey(response.getEphemeralPublicKey());
            createResponse.setActivationNonce(response.getActivationNonce());
            createResponse.setEncryptedServerPublicKey(response.getEncryptedServerPublicKey());
            createResponse.setEncryptedServerPublicKeySignature(response.getEncryptedServerPublicKeySignature());

            final ObjectResponse<NonPersonalizedEncryptedPayloadModel> powerAuthApiResponse = encryptor.encrypt(createResponse);

            if (activationProvider.shouldAutoCommitActivation(identity, customAttributes, response.getActivationId(), userId)) {
                powerAuthClient.commitActivation(response.getActivationId());
            }

            return powerAuthApiResponse;

        } catch (IOException | GenericCryptoException | CryptoProviderException | InvalidKeyException ex) {
            throw new PowerAuthActivationException();
        }

    }

}
