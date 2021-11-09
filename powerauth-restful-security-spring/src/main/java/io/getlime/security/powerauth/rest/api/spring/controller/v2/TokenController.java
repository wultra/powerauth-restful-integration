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
package io.getlime.security.powerauth.rest.api.spring.controller.v2;

import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthSignatureInvalidException;
import io.getlime.security.powerauth.rest.api.model.request.v2.TokenCreateRequest;
import io.getlime.security.powerauth.rest.api.model.request.v3.TokenRemoveRequest;
import io.getlime.security.powerauth.rest.api.model.response.v2.TokenCreateResponse;
import io.getlime.security.powerauth.rest.api.model.response.v3.TokenRemoveResponse;
import io.getlime.security.powerauth.rest.api.spring.annotation.PowerAuth;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller responsible for publishing services related to simple token-based authentication.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>2.0</li>
 *     <li>2.1</li>
 * </ul>
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("tokenControllerV2")
@RequestMapping("/pa/token")
public class TokenController {

    private static final Logger logger = LoggerFactory.getLogger(TokenController.class);

    private io.getlime.security.powerauth.rest.api.spring.service.v2.TokenService tokenServiceV2;
    private io.getlime.security.powerauth.rest.api.spring.service.v3.TokenService tokenServiceV3;

    /**
     * Set the token verification service via setter injection.
     * @param tokenServiceV2 Token verification service (v2).
     */
    @Autowired
    public void setTokenServiceV2(io.getlime.security.powerauth.rest.api.spring.service.v2.TokenService tokenServiceV2) {
        this.tokenServiceV2 = tokenServiceV2;
    }

    /**
     * Set the token verification service via setter injection.
     * @param tokenServiceV3 Token verification service (v3).
     */
    @Autowired
    public void setTokenServiceV3(io.getlime.security.powerauth.rest.api.spring.service.v3.TokenService tokenServiceV3) {
        this.tokenServiceV3 = tokenServiceV3;
    }

    /**
     * Create token.
     * @param request Create token request.
     * @param authentication PowerAuth API authentication object.
     * @return Create token response.
     * @throws PowerAuthAuthenticationException In case authentication fails or request is invalid.
     */
    @RequestMapping(value = "create", method = RequestMethod.POST)
    @PowerAuth(resourceId = "/pa/token/create", signatureType = {
            PowerAuthSignatureTypes.POSSESSION,
            PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE,
            PowerAuthSignatureTypes.POSSESSION_BIOMETRY,
            PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY
    })
    public ObjectResponse<TokenCreateResponse> createToken(
            @RequestBody ObjectRequest<TokenCreateRequest> request, PowerAuthApiAuthentication authentication) throws PowerAuthAuthenticationException {
        if (request.getRequestObject() == null) {
            logger.warn("Invalid request object in create token");
            throw new PowerAuthInvalidRequestException();
        }
        if (authentication == null || authentication.getActivationContext().getActivationId() == null) {
            logger.debug("Signature validation failed");
            throw new PowerAuthSignatureInvalidException();
        }
        if (!"2.0".equals(authentication.getVersion()) && !"2.1".equals(authentication.getVersion())) {
            logger.warn("Endpoint does not support PowerAuth protocol version {}", authentication.getVersion());
            throw new PowerAuthInvalidRequestException();
        }
        TokenCreateResponse response = tokenServiceV2.createToken(request.getRequestObject(), authentication);
        return new ObjectResponse<>(response);
    }

    /**
     * Remove token.
     * @param request Remove token request.
     * @param authentication PowerAuth API authentication object.
     * @return Remove token response.
     * @throws PowerAuthAuthenticationException In case authentication fails or request is invalid.
     */
    @RequestMapping(value = "remove", method = RequestMethod.POST)
    @PowerAuth(resourceId = "/pa/token/remove", signatureType = {
            PowerAuthSignatureTypes.POSSESSION,
            PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE,
            PowerAuthSignatureTypes.POSSESSION_BIOMETRY,
            PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY
    })
    public ObjectResponse<TokenRemoveResponse> removeToken(@RequestBody ObjectRequest<TokenRemoveRequest> request, PowerAuthApiAuthentication authentication) throws PowerAuthAuthenticationException {
        if (request.getRequestObject() == null) {
            logger.warn("Invalid request object in create token");
            throw new PowerAuthInvalidRequestException();
        }
        if (authentication == null || authentication.getActivationContext().getActivationId() == null) {
            logger.debug("Signature validation failed");
            throw new PowerAuthSignatureInvalidException();
        }
        if (!"2.0".equals(authentication.getVersion()) && !"2.1".equals(authentication.getVersion())) {
            logger.warn("Endpoint does not support PowerAuth protocol version {}", authentication.getVersion());
            throw new PowerAuthInvalidRequestException();
        }
        TokenRemoveResponse response = tokenServiceV3.removeToken(request.getRequestObject(), authentication);
        return new ObjectResponse<>(response);
    }

}
