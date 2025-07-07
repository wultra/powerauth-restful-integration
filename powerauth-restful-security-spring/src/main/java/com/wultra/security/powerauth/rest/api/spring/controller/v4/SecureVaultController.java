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

import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.request.AeadEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import com.wultra.security.powerauth.http.PowerAuthAuthorizationHttpHeader;
import com.wultra.security.powerauth.http.validator.InvalidPowerAuthHttpHeaderException;
import com.wultra.security.powerauth.http.validator.PowerAuthAuthorizationHttpHeaderValidator;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthSecureVaultException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthCodeInvalidException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import com.wultra.security.powerauth.rest.api.spring.service.v4.SecureVaultService;
import com.wultra.security.powerauth.rest.api.spring.util.PowerAuthVersionUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

/**
 * Controller implementing secure vault related end-points from the
 * PowerAuth Standard API.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>4.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@RestController("secureVaultControllerV4")
@RequestMapping("/pa/v4/vault")
@AllArgsConstructor
@Slf4j
public class SecureVaultController {

    private SecureVaultService secureVaultServiceV4;

    /**
     * Request the vault unlock key.
     *
     * @param authHeader PowerAuth authorization HTTP header.
     * @param request Request object encrypted by AEAD.
     * @param httpServletRequest HTTP servlet request.
     * @return Response object encrypted by AEAD.
     * @throws PowerAuthAuthenticationException In case authentication fails.
     * @throws PowerAuthSecureVaultException In case unlocking the vault fails.
     */
    @PostMapping("unlock")
    public AeadEncryptedResponse unlockVault(
            @RequestHeader(value = PowerAuthAuthorizationHttpHeader.HEADER_NAME, defaultValue = "unknown") String authHeader,
            @RequestBody AeadEncryptedRequest request,
            HttpServletRequest httpServletRequest)
            throws PowerAuthAuthenticationException, PowerAuthSecureVaultException {

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
            logger.warn("Authentication HTTP header validation failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthCodeInvalidException();
        }

        PowerAuthVersionUtil.checkUnsupportedVersionV4(header.getVersion());
        PowerAuthVersionUtil.checkEncryptionParameters(header.getVersion(), request);

        return secureVaultServiceV4.vaultUnlock(header, request, httpServletRequest);
    }

}
