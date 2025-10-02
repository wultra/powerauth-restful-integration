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
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorScope;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.request.AeadEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import com.wultra.security.powerauth.http.PowerAuthAuthorizationHttpHeader;
import com.wultra.security.powerauth.http.PowerAuthEncryptionHttpHeader;
import com.wultra.security.powerauth.http.validator.InvalidPowerAuthHttpHeaderException;
import com.wultra.security.powerauth.http.validator.PowerAuthAuthorizationHttpHeaderValidator;
import com.wultra.security.powerauth.http.validator.PowerAuthEncryptionHttpHeaderValidator;
import com.wultra.security.powerauth.rest.api.spring.annotation.PowerAuth;
import com.wultra.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthUpgradeException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import com.wultra.security.powerauth.rest.api.spring.service.UpgradeService;
import com.wultra.security.powerauth.rest.api.spring.util.PowerAuthAuthenticationUtil;
import com.wultra.security.powerauth.rest.api.spring.util.PowerAuthVersionUtil;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

/**
 * Controller responsible for upgrade from V3 to V4.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>4.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra
 */
@RestController
@AllArgsConstructor
@RequestMapping("/pa/v4/upgrade")
@Slf4j
public class UpgradeController {

    private UpgradeService upgradeService;

    /**
     * Start upgrade of activation to version 4.
     *
     * @param request AEAD encrypted request.
     * @param authorizationHeader Authorization HTTP header.
     * @param encryptionHeader Encryption HTTP header.
     * @param auth PowerAuth API authentication object.
     * @return AEAD encrypted response.
     * @throws PowerAuthUpgradeException In case upgrade fails.
     * @throws PowerAuthInvalidRequestException In case request is invalid.
     */
    @PostMapping("start")
    @PowerAuth(resourceId = "/pa/upgrade/start", authenticationCodeType = {
            PowerAuthCodeType.POSSESSION_KNOWLEDGE
    })
    public AeadEncryptedResponse upgradeStart(@RequestBody AeadEncryptedRequest request,
                                              @RequestHeader(value = PowerAuthAuthorizationHttpHeader.HEADER_NAME, defaultValue = "unknown") String authorizationHeader,
                                              @RequestHeader(value = PowerAuthEncryptionHttpHeader.HEADER_NAME, defaultValue = "unknown") String encryptionHeader,
                                              PowerAuthApiAuthentication auth)
            throws PowerAuthUpgradeException, PowerAuthAuthenticationException {

        if (request == null) {
            logger.warn("Invalid request object in upgrade start");
            throw new PowerAuthUpgradeException();
        }

        PowerAuthAuthenticationUtil.checkAuthentication(auth);

        // Parse the authorization header
        final PowerAuthAuthorizationHttpHeader authHeader = new PowerAuthAuthorizationHttpHeader().fromValue(authorizationHeader);

        // Validate the authorization header
        try {
            PowerAuthAuthorizationHttpHeaderValidator.validate(authHeader);
        } catch (InvalidPowerAuthHttpHeaderException ex) {
            logger.warn("Authorization HTTP header validation failed during upgrade start, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthUpgradeException();
        }

        // Parse the encryption header
        final PowerAuthEncryptionHttpHeader encHeader = new PowerAuthEncryptionHttpHeader().fromValue(encryptionHeader);

        // Validate the encryption header
        try {
            PowerAuthEncryptionHttpHeaderValidator.validate(encHeader, EncryptorScope.APPLICATION_SCOPE);
        } catch (InvalidPowerAuthHttpHeaderException ex) {
            logger.warn("Encryption HTTP header validation failed during upgrade start, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthUpgradeException();
        }


        PowerAuthVersionUtil.checkUnsupportedVersionV3(authHeader.getVersion());
        PowerAuthVersionUtil.checkUnsupportedVersionV4(encHeader.getVersion());
        PowerAuthVersionUtil.checkEncryptionParameters(encHeader.getVersion(), request);

        return upgradeService.upgradeStart(request, authHeader, encHeader);
    }

    /**
     * Confirm upgrade of activation to version 4.
     *
     * @param authorizationHeader PowerAuth authorization HTTP header.
     * @param auth PowerAuth API authentication object.
     * @return Response.
     * @throws PowerAuthAuthenticationException In case request authentication is invalid.
     * @throws PowerAuthUpgradeException In case confirmation fails.
     */
    @PostMapping("confirm")
    @PowerAuth(resourceId = "/pa/upgrade/confirm", authenticationCodeType = {
            PowerAuthCodeType.POSSESSION
    })
    public Response upgradeConfirm(@RequestHeader(value = PowerAuthAuthorizationHttpHeader.HEADER_NAME, defaultValue = "unknown") String authorizationHeader,
                                   PowerAuthApiAuthentication auth) throws PowerAuthAuthenticationException, PowerAuthUpgradeException {

        PowerAuthAuthenticationUtil.checkAuthentication(auth);

        // Parse the authorization header
        final PowerAuthAuthorizationHttpHeader header = new PowerAuthAuthorizationHttpHeader().fromValue(authorizationHeader);

        // Validate the authorization header
        try {
            PowerAuthAuthorizationHttpHeaderValidator.validate(header);
        } catch (InvalidPowerAuthHttpHeaderException ex) {
            logger.warn("Authorization HTTP header validation failed during upgrade confirmation, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthUpgradeException();
        }

        PowerAuthVersionUtil.checkUnsupportedVersionV4(header.getVersion());

        return upgradeService.upgradeConfirm(header);
    }
}
