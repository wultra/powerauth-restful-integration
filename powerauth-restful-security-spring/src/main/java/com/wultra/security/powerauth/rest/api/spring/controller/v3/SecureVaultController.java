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

import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedResponse;
import com.wultra.security.powerauth.http.PowerAuthAuthorizationHttpHeader;
import com.wultra.security.powerauth.http.validator.InvalidPowerAuthHttpHeaderException;
import com.wultra.security.powerauth.http.validator.PowerAuthAuthorizationHttpHeaderValidator;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthSecureVaultException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthCodeInvalidException;
import com.wultra.security.powerauth.rest.api.spring.service.v3.SecureVaultService;
import com.wultra.security.powerauth.rest.api.spring.util.PowerAuthVersionUtil;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Controller implementing secure vault related end-points from the
 * PowerAuth Standard API.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 *     <li>3.1</li>
 *     <li>3.2</li>
 *     <li>3.3</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@RestController("secureVaultControllerV3")
@RequestMapping("/pa/v3/vault")
@AllArgsConstructor
@Slf4j
public class SecureVaultController {

    private SecureVaultService secureVaultServiceV3;

    /**
     * Request the vault unlock key.
     *
     * @param authHeader PowerAuth authorization HTTP header.
     * @param request Request object encrypted by ECIES.
     * @param httpServletRequest HTTP servlet request.
     * @return Response object encrypted by ECIES.
     * @throws PowerAuthAuthenticationException In case authentication fails.
     * @throws PowerAuthSecureVaultException In case unlocking the vault fails.
     */
    @PostMapping("unlock")
    public EciesEncryptedResponse unlockVault(
            @RequestHeader(value = PowerAuthAuthorizationHttpHeader.HEADER_NAME, defaultValue = "unknown") String authHeader,
            @RequestBody EciesEncryptedRequest request,
            HttpServletRequest httpServletRequest)
            throws PowerAuthAuthenticationException, PowerAuthSecureVaultException {

        logger.info("action: unlockVault, state: initiated");
        if (request == null) {
            logger.warn("Invalid request object in vault unlock");
            throw new PowerAuthInvalidRequestException();
        }

        // Parse the header
        final PowerAuthAuthorizationHttpHeader header = new PowerAuthAuthorizationHttpHeader().fromValue(authHeader);

        // Validate the header
        try {
            PowerAuthAuthorizationHttpHeaderValidator.validate(header);
        } catch (InvalidPowerAuthHttpHeaderException ex) {
            logger.warn("Signature HTTP header validation failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthCodeInvalidException();
        }

        PowerAuthVersionUtil.checkUnsupportedVersionV3(header.getVersion());
        PowerAuthVersionUtil.checkEncryptionParameters(header.getVersion(), request);

        final EciesEncryptedResponse response = secureVaultServiceV3.vaultUnlock(header, request, httpServletRequest);
        logger.info("action: unlockVault, state: succeeded");
        return response;
    }

}
