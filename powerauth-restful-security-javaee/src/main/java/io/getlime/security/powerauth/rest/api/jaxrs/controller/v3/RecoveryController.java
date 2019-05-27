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

import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.jaxrs.provider.PowerAuthAuthenticationProvider;
import io.getlime.security.powerauth.rest.api.jaxrs.service.v3.RecoveryService;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import java.util.Collections;

/**
 * Controller implementing recovery related end-points from the PowerAuth
 * Standard API.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@Path("/pa/v3/recovery")
@Produces(MediaType.APPLICATION_JSON)
public class RecoveryController {

    private static final Logger logger = LoggerFactory.getLogger(RecoveryController.class);

    @Context
    private HttpServletRequest httpServletRequest;

    @Inject
    private PowerAuthAuthenticationProvider authenticationProvider;

    @Inject
    private RecoveryService recoveryService;

    /**
     * Confirm recovery code.
     * @param request ECIES encrypted request.
     * @return ECIES encrypted response.
     * @throws PowerAuthAuthenticationException In case confirm recovery fails.
     */
    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    @Path("confirm")
    public EciesEncryptedResponse confirmRecoveryCode(EciesEncryptedRequest request,
                                                      @HeaderParam(PowerAuthSignatureHttpHeader.HEADER_NAME) String authHeader) throws PowerAuthAuthenticationException {

        if (request == null) {
            logger.warn("Invalid request object in confirm recovery");
            throw new PowerAuthAuthenticationException();
        }
        // Verify request signature before creating token
        PowerAuthApiAuthentication authentication = authenticationProvider.validateRequestSignature(
                httpServletRequest, "/pa/recovery/confirm", authHeader,
                Collections.singletonList(
                        PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE
                ));
        if (authentication != null && authentication.getActivationId() != null) {
            if (!"3.0".equals(authentication.getVersion())) {
                logger.warn("Endpoint does not support PowerAuth protocol version {}", authentication.getVersion());
                throw new PowerAuthAuthenticationException();
            }
            return recoveryService.confirmRecoveryCode(request, authentication);
        } else {
            throw new PowerAuthAuthenticationException();
        }
    }

}
