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

import com.wultra.core.rest.model.base.response.Response;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorScope;
import com.wultra.security.powerauth.http.PowerAuthEncryptionHttpHeader;
import com.wultra.security.powerauth.http.PowerAuthSignatureHttpHeader;
import com.wultra.security.powerauth.http.validator.InvalidPowerAuthHttpHeaderException;
import com.wultra.security.powerauth.http.validator.PowerAuthEncryptionHttpHeaderValidator;
import com.wultra.security.powerauth.http.validator.PowerAuthSignatureHttpHeaderValidator;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthUpgradeException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import com.wultra.security.powerauth.rest.api.model.request.EciesEncryptedRequest;
import com.wultra.security.powerauth.rest.api.model.response.EciesEncryptedResponse;
import com.wultra.security.powerauth.rest.api.spring.service.UpgradeService;
import com.wultra.security.powerauth.rest.api.spring.util.PowerAuthVersionUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Controller responsible for upgrade.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 *     <li>3.1</li>
 *     <li>3.2</li>
 *     <li>3.3</li>
 *
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra
 */
@RestController
@RequestMapping("/pa/v3/upgrade")
public class UpgradeController {

    private static final Logger logger = LoggerFactory.getLogger(UpgradeController.class);

    private UpgradeService upgradeService;

    /**
     * Set upgrade service via setter injection.
     * @param upgradeService Upgrade service.
     */
    @Autowired
    public void setUpgradeService(UpgradeService upgradeService) {
        this.upgradeService = upgradeService;
    }

    /**
     * Start upgrade of activation to version 3.
     *
     * @param request ECIES encrypted request.
     * @param encryptionHeader Encryption HTTP header.
     * @return ECIES encrypted response.
     * @throws PowerAuthUpgradeException In case upgrade fails.
     */
    @PostMapping("start")
    public EciesEncryptedResponse upgradeStart(@RequestBody EciesEncryptedRequest request,
                                               @RequestHeader(value = PowerAuthEncryptionHttpHeader.HEADER_NAME, defaultValue = "unknown") String encryptionHeader)
            throws PowerAuthUpgradeException, PowerAuthInvalidRequestException {

        if (request == null) {
            logger.warn("Invalid request object in upgrade start");
            throw new PowerAuthUpgradeException();
        }

        // Parse the encryption header
        PowerAuthEncryptionHttpHeader header = new PowerAuthEncryptionHttpHeader().fromValue(encryptionHeader);

        // Validate the encryption header
        try {
            PowerAuthEncryptionHttpHeaderValidator.validate(header, EncryptorScope.ACTIVATION_SCOPE);
        } catch (InvalidPowerAuthHttpHeaderException ex) {
            logger.warn("Encryption validation failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthUpgradeException();
        }

        PowerAuthVersionUtil.checkUnsupportedVersion(header.getVersion());
        PowerAuthVersionUtil.checkEciesParameters(header.getVersion(), request);

        return upgradeService.upgradeStart(request, header);

    }

    /**
     * Commit upgrade of activation to version 3.
     *
     * @param signatureHeader PowerAuth signature HTTP header.
     * @param httpServletRequest HTTP servlet request.
     * @return Response.
     * @throws PowerAuthAuthenticationException In case request signature is invalid.
     * @throws PowerAuthUpgradeException In case commit fails.
     */
    @PostMapping("commit")
    public Response upgradeCommit(@RequestHeader(value = PowerAuthSignatureHttpHeader.HEADER_NAME) String signatureHeader,
                                  HttpServletRequest httpServletRequest)
            throws PowerAuthAuthenticationException, PowerAuthUpgradeException {

        // Parse the signature header
        PowerAuthSignatureHttpHeader header = new PowerAuthSignatureHttpHeader().fromValue(signatureHeader);

        // Validate the signature header
        try {
            PowerAuthSignatureHttpHeaderValidator.validate(header);
        } catch (InvalidPowerAuthHttpHeaderException ex) {
            logger.warn("Signature HTTP header validation failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthUpgradeException();
        }

        PowerAuthVersionUtil.checkUnsupportedVersion(header.getVersion());

        return upgradeService.upgradeCommit(signatureHeader, httpServletRequest);
    }
}
