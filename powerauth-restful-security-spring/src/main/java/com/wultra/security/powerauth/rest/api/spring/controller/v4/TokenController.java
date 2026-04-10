/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2025 Wultra s.r.o.
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

import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.request.AeadEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import com.wultra.security.powerauth.rest.api.model.request.TokenRemoveRequest;
import com.wultra.security.powerauth.rest.api.model.response.TokenRemoveResponse;
import com.wultra.security.powerauth.rest.api.spring.annotation.PowerAuth;
import com.wultra.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import com.wultra.security.powerauth.rest.api.spring.service.v4.TokenService;
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
 *     <li>4.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@RestController("tokenControllerV4")
@RequestMapping("/pa/v4/token")
@AllArgsConstructor
@Validated
@Slf4j
public class TokenController {

    private TokenService tokenServiceV4;

    /**
     * Create token.
     * @param request AEAD encrypted create token request.
     * @param auth PowerAuth API authentication object.
     * @return AEAD encrypted create token response.
     * @throws PowerAuthAuthenticationException In case authentication fails or request is invalid.
     */
    @PostMapping("create")
    @PowerAuth(resourceId = "/pa/token/create", authenticationCodeType = {
            PowerAuthCodeType.POSSESSION,
            PowerAuthCodeType.POSSESSION_KNOWLEDGE,
            PowerAuthCodeType.POSSESSION_BIOMETRY
    })
    public AeadEncryptedResponse createToken(@RequestBody AeadEncryptedRequest request,
                                             PowerAuthApiAuthentication auth)
            throws PowerAuthAuthenticationException {
        logger.info("action: createToken, state: initiated, activationId: {}",
                auth != null && auth.getActivationContext() != null ? auth.getActivationContext().getActivationId() : null);
        if (request == null) {
            logger.warn("Invalid request object in create token");
            throw new PowerAuthInvalidRequestException();
        }

        PowerAuthAuthenticationUtil.checkAuthentication(auth);
        PowerAuthVersionUtil.checkUnsupportedVersionV4(auth.getVersion());
        PowerAuthVersionUtil.checkEncryptionParameters(auth.getVersion(), request);

        final AeadEncryptedResponse response = tokenServiceV4.createToken(request, auth);
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
            PowerAuthCodeType.POSSESSION_BIOMETRY
    })
    public ObjectResponse<TokenRemoveResponse> removeToken(@Valid @RequestBody ObjectRequest<TokenRemoveRequest> request,
                                                           PowerAuthApiAuthentication auth) throws PowerAuthAuthenticationException {
        logger.info("action: removeToken, state: initiated, activationId: {}",
                auth != null && auth.getActivationContext() != null ? auth.getActivationContext().getActivationId() : null);

        PowerAuthAuthenticationUtil.checkAuthentication(auth);
        PowerAuthVersionUtil.checkUnsupportedVersionV4(auth.getVersion());

        final ObjectResponse<TokenRemoveResponse> response = new ObjectResponse<>(tokenServiceV4.removeToken(request.getRequestObject(), auth));
        logger.info("action: removeToken, state: succeeded");
        return response;
    }

}
