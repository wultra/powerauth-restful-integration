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
