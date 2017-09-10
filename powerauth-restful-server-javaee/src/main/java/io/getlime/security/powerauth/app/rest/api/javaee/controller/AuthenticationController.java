/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2017 Lime - HighTech Solutions s.r.o.
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

package io.getlime.security.powerauth.app.rest.api.javaee.controller;

import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.core.rest.model.base.response.Response;
import io.getlime.security.powerauth.http.PowerAuthHttpHeader;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.jaxrs.provider.PowerAuthAuthenticationProvider;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

/**
 * Simple demo controller class for signature validation purposes.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Path("pa/signature")
@Produces(MediaType.APPLICATION_JSON)
public class AuthenticationController {

    @Context
    private HttpServletRequest request;

    @Inject
    private PowerAuthAuthenticationProvider authenticationProvider;

    @POST
    @Path("validate")
    @Consumes("*/*")
    @Produces(MediaType.APPLICATION_JSON)
    public ObjectResponse<String> login(String body, @HeaderParam(value = PowerAuthHttpHeader.HEADER_NAME) String authHeader
    ) throws PowerAuthAuthenticationException {

        // ##EXAMPLE: Here, we could store the authentication in the session like this:
        // ##EXAMPLE: SecurityContextHolder.getContext().setAuthentication(apiAuthentication);
        // ##EXAMPLE: ... or you can grab a user ID like this and use it for querying back-end:
        // ##EXAMPLE: String userId = apiAuthentication.getUserId();

        PowerAuthApiAuthentication auth = authenticationProvider.validateRequestSignature(
                request,
                "/pa/signature/validate",
                authHeader
        );

        if (auth != null && auth.getUserId() != null) {
            return new ObjectResponse<>("Hooray! "
                    + " User: " + auth.getUserId()
                    + " (activation: " + auth.getActivationId() + ")"
                    + " successfully verified via app with ID: " + auth.getApplicationId()
                    + " using factor: " + auth.getSignatureFactors()
            );
        } else {
            throw new PowerAuthAuthenticationException("Authentication failed.");
        }

    }

}
