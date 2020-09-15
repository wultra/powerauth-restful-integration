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

import com.wultra.security.powerauth.client.v2.PowerAuthPortV2ServiceStub;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.util.Map;

/**
 * Sample controller for a custom activation implementation.
 *
 * <p><b>PowerAuth protocol versions:</b>
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

    private static final Logger logger = LoggerFactory.getLogger(CustomActivationController.class);

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
                logger.warn("Activation provider is missing");
                throw new PowerAuthActivationException();
            }

            ActivationCreateCustomRequest request = encryptor.decrypt(object, ActivationCreateCustomRequest.class);

            if (request == null) {
                logger.warn("Encryptor is not available");
                throw new PowerAuthActivationException();
            }

            final Map<String, String> identity = request.getIdentity();
            String userId = activationProvider.lookupUserIdForAttributes(identity);

            // If no user was found or user ID is invalid, return error
            if (userId == null || userId.equals("") || userId.length() > 255) {
                logger.warn("User ID is invalid: {}", userId);
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
            activationProvider.processCustomActivationAttributes(customAttributes, response.getActivationId(), userId, null, ActivationType.CUSTOM);

            ActivationCreateResponse createResponse = new ActivationCreateResponse();
            createResponse.setActivationId(response.getActivationId());
            createResponse.setEphemeralPublicKey(response.getEphemeralPublicKey());
            createResponse.setActivationNonce(response.getActivationNonce());
            createResponse.setEncryptedServerPublicKey(response.getEncryptedServerPublicKey());
            createResponse.setEncryptedServerPublicKeySignature(response.getEncryptedServerPublicKeySignature());

            final ObjectResponse<NonPersonalizedEncryptedPayloadModel> powerAuthApiResponse = encryptor.encrypt(createResponse);

            if (activationProvider.shouldAutoCommitActivation(identity, customAttributes, response.getActivationId(), userId, null, ActivationType.CUSTOM)) {
                powerAuthClient.commitActivation(response.getActivationId(), null);
            }

            return powerAuthApiResponse;

        } catch (Exception ex) {
            logger.warn("Create activation failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthActivationException();
        }

    }

}
