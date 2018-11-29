package io.getlime.security.powerauth.app.rest.api.javaee.controller;

import io.getlime.core.rest.model.base.response.Response;
import io.getlime.security.powerauth.http.PowerAuthTokenHttpHeader;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.jaxrs.provider.PowerAuthAuthenticationProvider;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;

/**
 * Simple demo controller class for token validation purposes.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Path("token")
@Produces(MediaType.APPLICATION_JSON)
public class TokenController {

    @Inject
    private PowerAuthAuthenticationProvider authenticationProvider;

    @POST
    @Path("authorize")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response authorize(@HeaderParam(value = PowerAuthTokenHttpHeader.HEADER_NAME) String tokenHeader) throws PowerAuthAuthenticationException {
        PowerAuthApiAuthentication auth = authenticationProvider.validateToken(tokenHeader);
        if (auth != null && auth.getUserId() != null) {
            return new Response();
        } else {
            throw new PowerAuthAuthenticationException("Authentication failed.");
        }
    }

}
