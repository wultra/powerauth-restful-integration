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
package io.getlime.security.powerauth.rest.api.spring.controller.v3;

import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.rest.api.base.encryption.EciesEncryptionContext;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthRecoveryException;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import io.getlime.security.powerauth.rest.api.spring.annotation.PowerAuth;
import io.getlime.security.powerauth.rest.api.spring.service.v3.RecoveryService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

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
     * @param request Ecies encrypted request.
     * @param eciesContext Ecies encryption context.
     * @return Ecies encrypted response.
     * @throws PowerAuthRecoveryException In case confirm recovery fails.
     */
    @RequestMapping(value = "confirm", method = RequestMethod.POST)
    @PowerAuth(resourceId = "/pa/recovery/confirm", signatureType = {
            PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE
    })
    public EciesEncryptedResponse createActivation(@RequestBody EciesEncryptedRequest request,
                                                   EciesEncryptionContext eciesContext) throws PowerAuthRecoveryException {
        if (request == null || eciesContext == null) {
            logger.warn("Invalid request object in confirm recovery");
            throw new PowerAuthRecoveryException();
        }
        return recoveryService.confirmRecoveryCode(request, eciesContext);
    }

}