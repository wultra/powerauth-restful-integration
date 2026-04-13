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
package com.wultra.security.powerauth.rest.api.spring.controller.v4;

import com.wultra.core.rest.model.base.response.Response;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.rest.api.spring.annotation.PowerAuth;
import com.wultra.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import com.wultra.security.powerauth.rest.api.spring.util.PowerAuthAuthenticationUtil;
import com.wultra.security.powerauth.rest.api.spring.util.PowerAuthVersionUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * End-point for validating authentication codes.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>4.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@RestController("authenticationControllerV4")
@RequestMapping("/pa/v4/auth")
@Slf4j
public class AuthenticationController {

    /**
     * Validate authentication code by validating any data sent in request to this end-point.
     * @param auth Automatically injected PowerAuth authentication object.
     * @return API response with success.
     * @throws PowerAuthAuthenticationException In case any error occurs, including authentication code validation errors.
     */
    @RequestMapping(value = "validate", method = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE})
    @PowerAuth(resourceId = "/pa/auth/validate", authenticationCodeType = {
            PowerAuthCodeType.POSSESSION,
            PowerAuthCodeType.POSSESSION_KNOWLEDGE,
            PowerAuthCodeType.POSSESSION_BIOMETRY
    })
    public Response validateAuthentication(PowerAuthApiAuthentication auth) throws PowerAuthAuthenticationException {
        logger.info("action: validateAuthentication, state: initiated, activationId: {}",
                auth != null && auth.getActivationContext() != null ? auth.getActivationContext().getActivationId() : null);

        PowerAuthAuthenticationUtil.checkAuthentication(auth);
        PowerAuthVersionUtil.checkUnsupportedVersionV4(auth.getVersion());

        logger.info("action: validateAuthentication, state: succeeded");
        return new Response();
    }

}
