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
package io.getlime.security.powerauth.rest.api.jaxrs.controller.v2;

import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthActivationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.jaxrs.provider.PowerAuthAuthenticationProvider;
import io.getlime.security.powerauth.rest.api.model.request.v2.ActivationCreateRequest;
import io.getlime.security.powerauth.rest.api.model.request.v3.ActivationStatusRequest;
import io.getlime.security.powerauth.rest.api.model.response.v2.ActivationCreateResponse;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationRemoveResponse;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationStatusResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;

/**
 * Controller implementing activation related end-points from the PowerAuth
 * Standard API.
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
@Path("pa/activation")
@Produces(MediaType.APPLICATION_JSON)
public class ActivationController {

    private static final Logger logger = LoggerFactory.getLogger(ActivationController.class);

    @Inject
    private io.getlime.security.powerauth.rest.api.jaxrs.service.v2.ActivationService activationServiceV2;

    @Inject
    private io.getlime.security.powerauth.rest.api.jaxrs.service.v3.ActivationService activationServiceV3;

    @Inject
    private PowerAuthAuthenticationProvider authenticationProvider;

    /**
     * Create a new activation.
     * @param request PowerAuth RESTful request with {@link ActivationCreateRequest} payload.
     * @return PowerAuth RESTful response with {@link ActivationCreateResponse} payload.
     * @throws PowerAuthActivationException In case creating activation fails.
     */
    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    @Path("create")
    public ObjectResponse<ActivationCreateResponse> createActivation(ObjectRequest<ActivationCreateRequest> request) throws PowerAuthActivationException {
        if (request.getRequestObject() == null || request.getRequestObject().getActivationIdShort() == null) {
            logger.warn("Invalid request object in activation create");
            throw new PowerAuthActivationException();
        }
        return new ObjectResponse<>(activationServiceV2.createActivation(request.getRequestObject()));
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
        // Request body needs to be set to null because the SDK uses null for the signature, although {} is sent as request body
        PowerAuthApiAuthentication apiAuthentication = authenticationProvider.validateRequestSignature("POST", null, "/pa/activation/remove", signatureHeader);
        if (apiAuthentication == null || apiAuthentication.getActivationId() == null) {
            throw new PowerAuthAuthenticationException("POWER_AUTH_SIGNATURE_INVALID");
        }
        if (!"2.0".equals(apiAuthentication.getVersion()) && !"2.1".equals(apiAuthentication.getVersion())) {
            logger.warn("Endpoint does not support PowerAuth protocol version {}", apiAuthentication.getVersion());
            throw new PowerAuthAuthenticationException();
        }
        return new ObjectResponse<>(activationServiceV3.removeActivation(apiAuthentication));
    }


}
