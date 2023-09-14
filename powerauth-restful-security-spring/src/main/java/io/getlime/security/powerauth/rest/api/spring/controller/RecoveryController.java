/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2019 Wultra s.r.o.
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
package io.getlime.security.powerauth.rest.api.spring.controller;

import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthSignatureInvalidException;
import io.getlime.security.powerauth.rest.api.model.request.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.EciesEncryptedResponse;
import io.getlime.security.powerauth.rest.api.spring.annotation.PowerAuth;
import io.getlime.security.powerauth.rest.api.spring.service.RecoveryService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import static io.getlime.security.powerauth.rest.api.spring.util.PowerAuthVersionUtil.*;

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
@RestController
@RequestMapping(value = "/pa/v3/recovery")
public class RecoveryController {

    private static final Logger logger = LoggerFactory.getLogger(RecoveryController.class);

    private final RecoveryService recoveryService;

    /**
     * Service constructor.
     * @param recoveryService Recovery service.
     */
    public RecoveryController(RecoveryService recoveryService) {
        this.recoveryService = recoveryService;
    }

    /**
     * Confirm recovery code.
     * @param request ECIES encrypted request.
     * @param authentication PowerAuth API authentication object.
     * @return ECIES encrypted response.
     * @throws PowerAuthAuthenticationException In case confirm recovery fails.
     */
    @PostMapping("confirm")
    @PowerAuth(resourceId = "/pa/recovery/confirm", signatureType = {
            PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE
    })
    public EciesEncryptedResponse confirmRecoveryCode(@RequestBody EciesEncryptedRequest request,
                                                      PowerAuthApiAuthentication authentication) throws PowerAuthAuthenticationException {
        if (request == null) {
            logger.warn("Invalid request object in confirm recovery");
            throw new PowerAuthInvalidRequestException();
        }
        if (authentication == null || authentication.getActivationContext().getActivationId() == null) {
            throw new PowerAuthSignatureInvalidException();
        }

        checkUnsupportedVersion(authentication.getVersion(), PowerAuthInvalidRequestException::new);
        checkMissingRequiredNonce(authentication.getVersion(), request.getNonce(), PowerAuthInvalidRequestException::new);
        checkMissingRequiredTimestamp(authentication.getVersion(), request.getTimestamp(), PowerAuthInvalidRequestException::new);

        return recoveryService.confirmRecoveryCode(request, authentication);
    }

}