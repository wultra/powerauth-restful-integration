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
package com.wultra.security.powerauth.rest.api.spring.controller.v3;

import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.rest.api.model.request.TokenRemoveRequest;
import com.wultra.security.powerauth.rest.api.model.response.TokenRemoveResponse;
import com.wultra.security.powerauth.rest.api.spring.annotation.PowerAuth;
import com.wultra.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import com.wultra.security.powerauth.rest.api.spring.service.v3.TokenService;
import com.wultra.security.powerauth.rest.api.spring.util.PowerAuthAuthenticationUtil;
import com.wultra.security.powerauth.rest.api.spring.util.PowerAuthVersionUtil;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.validation.annotation.Validated;
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
@AllArgsConstructor
@Validated
@Slf4j
public class TokenController {

    private TokenService tokenServiceV3;

    /**
     * Create token.
     * @param request ECIES encrypted create token request.
     * @param auth PowerAuth API authentication object.
     * @return ECIES encrypted create token response.
     * @throws PowerAuthAuthenticationException In case authentication fails or request is invalid.
     */
    @PostMapping("create")
    @PowerAuth(resourceId = "/pa/token/create", authenticationCodeType = {
            PowerAuthCodeType.POSSESSION,
            PowerAuthCodeType.POSSESSION_KNOWLEDGE,
            PowerAuthCodeType.POSSESSION_BIOMETRY,
            PowerAuthCodeType.POSSESSION_KNOWLEDGE_BIOMETRY
    })
    public EciesEncryptedResponse createToken(@RequestBody EciesEncryptedRequest request,
                                              PowerAuthApiAuthentication auth)
            throws PowerAuthAuthenticationException {
        logger.info("action: createToken, state: initiated, activationId: {}",
                auth != null && auth.getActivationContext() != null ? auth.getActivationContext().getActivationId() : null);
        if (request == null) {
            logger.warn("Invalid request object in create token");
            throw new PowerAuthInvalidRequestException();
        }

        PowerAuthAuthenticationUtil.checkAuthentication(auth);
        PowerAuthVersionUtil.checkUnsupportedVersionV3(auth.getVersion());
        PowerAuthVersionUtil.checkEncryptionParameters(auth.getVersion(), request);

        final EciesEncryptedResponse response = tokenServiceV3.createToken(request, auth);
        logger.info("action: createToken, state: succeeded");
        return response;
    }

    /**
     * Remove token.
     * @param request Remove token request.
     * @param auth PowerAuth API authentication object.
     * @return Remove token response.
     * @throws PowerAuthAuthenticationException In case authentication fails or request is invalid.
     */
    @PostMapping("remove")
    @PowerAuth(resourceId = "/pa/token/remove", authenticationCodeType = {
            PowerAuthCodeType.POSSESSION,
            PowerAuthCodeType.POSSESSION_KNOWLEDGE,
            PowerAuthCodeType.POSSESSION_BIOMETRY,
            PowerAuthCodeType.POSSESSION_KNOWLEDGE_BIOMETRY
    })
    public ObjectResponse<TokenRemoveResponse> removeToken(@Valid @RequestBody ObjectRequest<TokenRemoveRequest> request,
                                                           PowerAuthApiAuthentication auth) throws PowerAuthAuthenticationException {
        logger.info("action: removeToken, state: initiated, activationId: {}",
                auth != null && auth.getActivationContext() != null ? auth.getActivationContext().getActivationId() : null);

        PowerAuthAuthenticationUtil.checkAuthentication(auth);
        PowerAuthVersionUtil.checkUnsupportedVersionV3(auth.getVersion());

        final ObjectResponse<TokenRemoveResponse> response = new ObjectResponse<>(tokenServiceV3.removeToken(request.getRequestObject(), auth));
        logger.info("action: removeToken, state: succeeded");
        return response;
    }

}
