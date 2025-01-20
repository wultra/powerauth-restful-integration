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
package com.wultra.security.powerauth.rest.api.spring.controller;

import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import com.wultra.security.powerauth.rest.api.model.request.EciesEncryptedRequest;
import com.wultra.security.powerauth.rest.api.model.request.TokenRemoveRequest;
import com.wultra.security.powerauth.rest.api.model.response.EciesEncryptedResponse;
import com.wultra.security.powerauth.rest.api.model.response.TokenRemoveResponse;
import com.wultra.security.powerauth.rest.api.spring.annotation.PowerAuth;
import com.wultra.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import com.wultra.security.powerauth.rest.api.spring.service.TokenService;
import com.wultra.security.powerauth.rest.api.spring.util.PowerAuthAuthenticationUtil;
import com.wultra.security.powerauth.rest.api.spring.util.PowerAuthVersionUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller responsible for publishing services related to simple token-based authentication.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 *     <li>3.1</li>
 *     <li>3.2</li>
 *     <li>3.3</li>
 * </ul>
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController("tokenControllerV3")
@RequestMapping("/pa/v3/token")
public class TokenController {

    private static final Logger logger = LoggerFactory.getLogger(TokenController.class);

    private TokenService tokenServiceV3;

    /**
     * Set the token verification service via setter injection.
     * @param tokenServiceV3 Token verification service.
     */
    @Autowired
    public void setTokenServiceV3(TokenService tokenServiceV3) {
        this.tokenServiceV3 = tokenServiceV3;
    }

    /**
     * Create token.
     * @param request ECIES encrypted create token request.
     * @param auth PowerAuth API authentication object.
     * @return ECIES encrypted create token response.
     * @throws PowerAuthAuthenticationException In case authentication fails or request is invalid.
     */
    @PostMapping("create")
    @PowerAuth(resourceId = "/pa/token/create", signatureType = {
            PowerAuthSignatureTypes.POSSESSION,
            PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE,
            PowerAuthSignatureTypes.POSSESSION_BIOMETRY,
            PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY
    })
    public EciesEncryptedResponse createToken(@RequestBody EciesEncryptedRequest request,
                                              PowerAuthApiAuthentication auth)
            throws PowerAuthAuthenticationException {
        if (request == null) {
            logger.warn("Invalid request object in create token");
            throw new PowerAuthInvalidRequestException();
        }

        PowerAuthAuthenticationUtil.checkAuthentication(auth);
        PowerAuthVersionUtil.checkUnsupportedVersion(auth.getVersion());
        PowerAuthVersionUtil.checkEciesParameters(auth.getVersion(), request);

        return tokenServiceV3.createToken(request, auth);
    }

    /**
     * Remove token.
     * @param request Remove token request.
     * @param auth PowerAuth API authentication object.
     * @return Remove token response.
     * @throws PowerAuthAuthenticationException In case authentication fails or request is invalid.
     */
    @PostMapping("remove")
    @PowerAuth(resourceId = "/pa/token/remove", signatureType = {
            PowerAuthSignatureTypes.POSSESSION,
            PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE,
            PowerAuthSignatureTypes.POSSESSION_BIOMETRY,
            PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY
    })
    public ObjectResponse<TokenRemoveResponse> removeToken(@RequestBody ObjectRequest<TokenRemoveRequest> request,
                                                           PowerAuthApiAuthentication auth) throws PowerAuthAuthenticationException {
        if (request.getRequestObject() == null) {
            logger.warn("Invalid request object in remove token");
            throw new PowerAuthInvalidRequestException();
        }

        PowerAuthAuthenticationUtil.checkAuthentication(auth);
        PowerAuthVersionUtil.checkUnsupportedVersion(auth.getVersion());

        TokenRemoveResponse response = tokenServiceV3.removeToken(request.getRequestObject(), auth);
        return new ObjectResponse<>(response);
    }

}
