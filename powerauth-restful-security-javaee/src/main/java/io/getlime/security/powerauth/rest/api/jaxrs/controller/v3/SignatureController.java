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

import io.getlime.core.rest.model.base.response.Response;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.jaxrs.provider.PowerAuthAuthenticationProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import java.util.Arrays;

/**
 * End-point for validating signatures.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@Path("pa/v3/signature")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class SignatureController {

    private static final Logger logger = LoggerFactory.getLogger(SignatureController.class);

    @Context
    private HttpServletRequest httpServletRequest;

    @Inject
    private PowerAuthAuthenticationProvider authenticationProvider;

    /**
     * Validate signature by validating any data sent in GET request to this end-point.
     * @param authHeader PowerAuth authentication HTTP header.
     * @return API response with success.
     * @throws PowerAuthAuthenticationException In case any error occurs, including signature validation errors.
     */
    @GET
    @Path("validate")
    public Response validateSignatureGet(@HeaderParam(PowerAuthSignatureHttpHeader.HEADER_NAME) String authHeader) throws PowerAuthAuthenticationException {
        return validateSignature(authHeader);
    }

    /**
     * Validate signature by validating any data sent in POST request to this end-point.
     * @param authHeader PowerAuth authentication HTTP header.
     * @return API response with success.
     * @throws PowerAuthAuthenticationException In case any error occurs, including signature validation errors.
     */
    @POST
    @Path("validate")
    public Response validateSignaturePost(@HeaderParam(PowerAuthSignatureHttpHeader.HEADER_NAME) String authHeader) throws PowerAuthAuthenticationException {
        return validateSignature(authHeader);
    }

    /**
     * Validate signature by validating any data sent in PUT request to this end-point.
     * @param authHeader PowerAuth authentication HTTP header.
     * @return API response with success.
     * @throws PowerAuthAuthenticationException In case any error occurs, including signature validation errors.
     */
    @PUT
    @Path("validate")
    public Response validateSignaturePut(@HeaderParam(PowerAuthSignatureHttpHeader.HEADER_NAME) String authHeader) throws PowerAuthAuthenticationException {
        return validateSignature(authHeader);
    }

    /**
     * Validate signature by validating any data sent in DELETE request to this end-point.
     * @param authHeader PowerAuth authentication HTTP header.
     * @return API response with success.
     * @throws PowerAuthAuthenticationException In case any error occurs, including signature validation errors.
     */
    @DELETE
    @Path("validate")
    public Response validateSignatureDelete(@HeaderParam(PowerAuthSignatureHttpHeader.HEADER_NAME) String authHeader) throws PowerAuthAuthenticationException {
        return validateSignature(authHeader);
    }

    /**
     * Signature validation logic.
     * @param authHeader PowerAuth authentication header.
     * @return Response with Status.OK when signature validation succeeds.
     * @throws PowerAuthAuthenticationException Thrown when signature validation fails or any other error occurs.
     */
    private Response validateSignature(String authHeader) throws PowerAuthAuthenticationException {
        try {
            PowerAuthApiAuthentication authentication = authenticationProvider.validateRequestSignature(
                    httpServletRequest,
                    "/pa/signature/validate",
                    authHeader,
                    Arrays.asList(
                            PowerAuthSignatureTypes.POSSESSION,
                            PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE,
                            PowerAuthSignatureTypes.POSSESSION_BIOMETRY,
                            PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY
                    )
            );
            if (authentication != null && authentication.getActivationId() != null) {
                if (!"3.0".equals(authentication.getVersion()) && !"3.1".equals(authentication.getVersion())) {
                    logger.warn("Endpoint does not support PowerAuth protocol version {}", authentication.getVersion());
                    throw new PowerAuthAuthenticationException("POWER_AUTH_REQUEST_INVALID");
                }
                return new Response();
            } else {
                throw new PowerAuthAuthenticationException("POWER_AUTH_SIGNATURE_INVALID");
            }
        } catch (PowerAuthAuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            logger.warn("Signature validation failed, error: {}", ex.getMessage());
            throw new PowerAuthAuthenticationException("POWER_AUTH_SIGNATURE_ERROR");
        }
    }
}
