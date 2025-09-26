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
package com.wultra.security.powerauth.rest.api.spring.service;

import com.wultra.core.rest.model.base.response.Response;
import com.wultra.security.powerauth.client.model.request.v4.ConfirmUpgradeRequest;
import com.wultra.security.powerauth.client.model.request.v4.StartUpgradeRequest;
import com.wultra.security.powerauth.client.model.response.v4.ConfirmUpgradeResponse;
import com.wultra.security.powerauth.client.model.response.v4.StartUpgradeResponse;
import com.wultra.security.powerauth.client.v4.PowerAuthClient;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.request.AeadEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import com.wultra.security.powerauth.http.PowerAuthAuthorizationHttpHeader;
import com.wultra.security.powerauth.http.PowerAuthEncryptionHttpHeader;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthUpgradeException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Service implementing upgrade functionality.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>4.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@Service
@AllArgsConstructor
@Slf4j
public class UpgradeService {

    private final PowerAuthClient powerAuthClient;
    private final HttpCustomizationService httpCustomizationService;

    /**
     * Start upgrade of activation to version 4.
     * @param request AEAD encrypted upgrade start request.
     * @param authHeader PowerAuth authentication HTTP header.
     * @param encHeader PowerAuth encryption HTTP header.
     * @return AEAD encrypted upgrade activation response.
     * @throws PowerAuthUpgradeException In case upgrade start fails.
     */
    public AeadEncryptedResponse upgradeStart(AeadEncryptedRequest request, PowerAuthAuthorizationHttpHeader authHeader, PowerAuthEncryptionHttpHeader encHeader)
            throws PowerAuthUpgradeException {

        try {
            // Extract values from headers, activation ID is from authentication, the rest from encryption
            final String activationId = authHeader.getActivationId();
            final String applicationKey = encHeader.getApplicationKey();
            final String version = encHeader.getVersion();

            // Start upgrade on PowerAuth server
            final StartUpgradeRequest upgradeRequest = new StartUpgradeRequest();
            upgradeRequest.setActivationId(activationId);
            upgradeRequest.setApplicationKey(applicationKey);
            upgradeRequest.setTemporaryKeyId(request.getTemporaryKeyId());
            upgradeRequest.setEncryptedData(request.getEncryptedData());
            upgradeRequest.setNonce(request.getNonce());
            upgradeRequest.setProtocolVersion(version);
            upgradeRequest.setTimestamp(request.getTimestamp());
            final StartUpgradeResponse upgradeResponse = powerAuthClient.startUpgrade(
                    upgradeRequest,
                    httpCustomizationService.getQueryParams(),
                    httpCustomizationService.getHttpHeaders()
            );

            // Prepare a response
            final AeadEncryptedResponse response = new AeadEncryptedResponse();
            response.setEncryptedData(upgradeResponse.getEncryptedData());
            response.setTimestamp(upgradeResponse.getTimestamp());
            return response;
        } catch (Exception ex) {
            logger.warn("PowerAuth upgrade start failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthUpgradeException();
        }
    }

    /**
     * Confirm upgrade of activation to version 4.
     * @param header PowerAuth authorization HTTP header.
     * @return Confirm upgrade response.
     * @throws PowerAuthUpgradeException In case upgrade confirmation fails.
     */
    public Response upgradeConfirm(PowerAuthAuthorizationHttpHeader header) throws PowerAuthUpgradeException {

        try {
            // Get HTTP headers
            final String activationId = header.getActivationId();
            final String applicationKey = header.getApplicationKey();

            // Confirm upgrade on PowerAuth server
            final ConfirmUpgradeRequest request = new ConfirmUpgradeRequest();
            request.setActivationId(activationId);
            request.setApplicationKey(applicationKey);
            final ConfirmUpgradeResponse upgradeResponse = powerAuthClient.confirmUpgrade(
                    request,
                    httpCustomizationService.getQueryParams(),
                    httpCustomizationService.getHttpHeaders()
            );

            if (upgradeResponse.isConfirmed()) {
                return new Response();
            } else {
                logger.debug("Upgrade confirmation failed");
                throw new PowerAuthUpgradeException();
            }
        } catch (Exception ex) {
            logger.warn("PowerAuth upgrade confirmation failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthUpgradeException();
        }
    }

}
