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
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.http.PowerAuthTokenHttpHeader;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.jaxrs.provider.PowerAuthAuthenticationProvider;
import io.getlime.security.powerauth.rest.api.jaxrs.service.v3.TokenService;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.request.v3.TokenRemoveRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import io.getlime.security.powerauth.rest.api.model.response.v3.TokenRemoveResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import java.util.Arrays;

/**
 * Controller responsible for publishing services related to simple token-based authentication.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Path("pa/v3/token")
@Produces(MediaType.APPLICATION_JSON)
public class TokenController {

    private static final Logger logger = LoggerFactory.getLogger(TokenController.class);

    @Context
    private HttpServletRequest httpServletRequest;

    @Inject
    private TokenService tokenServiceV3;

    @Inject
    private PowerAuthAuthenticationProvider authenticationProvider;

    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    @Path("create")
    public EciesEncryptedResponse createToken(EciesEncryptedRequest request,
                                              @HeaderParam(PowerAuthTokenHttpHeader.HEADER_NAME) String tokenHeader,
                                              @HeaderParam(PowerAuthSignatureHttpHeader.HEADER_NAME) String authHeader) throws PowerAuthAuthenticationException {

        if (request == null) {
            logger.warn("Invalid request object in create token");
            throw new PowerAuthAuthenticationException();
        }
        // Verify request signature before creating token
        PowerAuthApiAuthentication authentication = authenticationProvider.validateRequestSignature(
                httpServletRequest, "/pa/token/create", authHeader,
                Arrays.asList(
                        PowerAuthSignatureTypes.POSSESSION,
                        PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE,
                        PowerAuthSignatureTypes.POSSESSION_BIOMETRY,
                        PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY
                ));
        if (authentication != null && authentication.getActivationId() != null) {
            if (!"3.0".equals(authentication.getVersion())) {
                logger.warn("Endpoint does not support PowerAuth protocol version {}", authentication.getVersion());
                throw new PowerAuthAuthenticationException();
            }
            return tokenServiceV3.createToken(request, authentication);
        } else {
            throw new PowerAuthAuthenticationException();
        }
    }

    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    @Path("remove")
    public ObjectResponse<TokenRemoveResponse> removeToken(ObjectRequest<TokenRemoveRequest> request,
                                                           @HeaderParam(PowerAuthTokenHttpHeader.HEADER_NAME) String tokenHeader,
                                                           @HeaderParam(PowerAuthSignatureHttpHeader.HEADER_NAME) String authHeader) throws PowerAuthAuthenticationException {
        if (request.getRequestObject() == null) {
            logger.warn("Invalid request object in remove token");
            throw new PowerAuthAuthenticationException();
        }

        // Verify request signature before removing token
        PowerAuthApiAuthentication authentication = authenticationProvider.validateRequestSignature(
                httpServletRequest, "/pa/token/remove", authHeader,
                Arrays.asList(
                        PowerAuthSignatureTypes.POSSESSION,
                        PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE,
                        PowerAuthSignatureTypes.POSSESSION_BIOMETRY,
                        PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY
                ));

        if (authentication != null && authentication.getActivationId() != null) {
            if (!"3.0".equals(authentication.getVersion())) {
                logger.warn("Endpoint does not support PowerAuth protocol version {}", authentication.getVersion());
                throw new PowerAuthAuthenticationException();
            }
            return new ObjectResponse<>(tokenServiceV3.removeToken(request.getRequestObject(), authentication));
        } else {
            throw new PowerAuthAuthenticationException();
        }
    }

}
