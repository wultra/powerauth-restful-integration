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
package io.getlime.security.powerauth.rest.api.jaxrs.controller.v3;

import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesScope;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.encryption.PowerAuthEciesEncryption;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthActivationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthEncryptionException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthRecoveryException;
import io.getlime.security.powerauth.rest.api.jaxrs.provider.PowerAuthAuthenticationProvider;
import io.getlime.security.powerauth.rest.api.jaxrs.provider.PowerAuthEncryptionProvider;
import io.getlime.security.powerauth.rest.api.model.request.v3.ActivationLayer1Request;
import io.getlime.security.powerauth.rest.api.model.request.v3.ActivationStatusRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationLayer1Response;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationRemoveResponse;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationStatusResponse;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

/**
 * Controller implementing activation related end-points from the PowerAuth
 * Standard API.
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
@Path("pa/v3/activation")
@Produces(MediaType.APPLICATION_JSON)
public class ActivationController {

    private static final Logger logger = LoggerFactory.getLogger(ActivationController.class);

    @Inject
    private io.getlime.security.powerauth.rest.api.jaxrs.service.v3.ActivationService activationServiceV3;

    @Inject
    private PowerAuthAuthenticationProvider authenticationProvider;

    @Inject
    private PowerAuthEncryptionProvider encryptionProvider;

    @Context
    private HttpServletRequest httpServletRequest;

    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    @Path("create")
    public EciesEncryptedResponse createActivation() throws PowerAuthActivationException, PowerAuthRecoveryException {
        try {
            PowerAuthEciesEncryption<ActivationLayer1Request> eciesEncryption = encryptionProvider.decryptRequest(httpServletRequest, ActivationLayer1Request.class, EciesScope.APPLICATION_SCOPE);
            ActivationLayer1Request layer1Request = eciesEncryption.getRequestObject();
            ActivationLayer1Response layer1Response = activationServiceV3.createActivation(layer1Request, eciesEncryption);
            return encryptionProvider.encryptResponse(layer1Response, eciesEncryption);
        } catch (PowerAuthEncryptionException ex) {
            logger.warn("Encryption failed, error: {}", ex.getMessage());
            throw new PowerAuthActivationException();
        }
    }

    /**
     * Get activation status.
     * @param request PowerAuth RESTful request with {@link ActivationStatusRequest} payload.
     * @return PowerAuth RESTful response with {@link ActivationStatusResponse} payload.
     * @throws PowerAuthActivationException In case request fails.
     */
    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    @Path("status")
    public ObjectResponse<ActivationStatusResponse> getActivationStatus(ObjectRequest<ActivationStatusRequest> request) throws PowerAuthActivationException {
        if (request.getRequestObject() == null || request.getRequestObject().getActivationId() == null) {
            logger.warn("Invalid request object in activation status");
            throw new PowerAuthActivationException();
        }
        return new ObjectResponse<>(activationServiceV3.getActivationStatus(request.getRequestObject()));
    }

    /**
     * Remove activation.
     * @param signatureHeader PowerAuth signature HTTP header.
     * @return PowerAuth RESTful response with {@link ActivationRemoveResponse} payload.
     * @throws PowerAuthAuthenticationException In case the signature validation fails.
     * @throws PowerAuthActivationException In case remove request fails.
     */
    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    @Path("remove")
    public ObjectResponse<ActivationRemoveResponse> removeActivation(@HeaderParam(PowerAuthSignatureHttpHeader.HEADER_NAME) String signatureHeader) throws PowerAuthAuthenticationException, PowerAuthActivationException {
        byte[] requestBodyBytes = authenticationProvider.extractRequestBodyBytes(httpServletRequest);
        PowerAuthApiAuthentication apiAuthentication = authenticationProvider.validateRequestSignature("POST", requestBodyBytes, "/pa/activation/remove", signatureHeader);
        if (apiAuthentication == null || apiAuthentication.getActivationId() == null) {
            throw new PowerAuthAuthenticationException("POWER_AUTH_REQUEST_INVALID");
        }
        if (!"3.0".equals(apiAuthentication.getVersion()) && !"3.1".equals(apiAuthentication.getVersion())) {
            logger.warn("Endpoint does not support PowerAuth protocol version {}", apiAuthentication.getVersion());
            throw new PowerAuthAuthenticationException("POWER_AUTH_REQUEST_INVALID");
        }
        return new ObjectResponse<>(activationServiceV3.removeActivation(apiAuthentication));
    }


}
