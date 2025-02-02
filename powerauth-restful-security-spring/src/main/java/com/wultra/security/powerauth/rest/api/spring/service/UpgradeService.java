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

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.request.CommitUpgradeRequest;
import com.wultra.security.powerauth.client.model.request.StartUpgradeRequest;
import com.wultra.security.powerauth.client.model.response.CommitUpgradeResponse;
import com.wultra.security.powerauth.client.model.response.StartUpgradeResponse;
import com.wultra.core.rest.model.base.response.Response;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import com.wultra.security.powerauth.http.PowerAuthEncryptionHttpHeader;
import com.wultra.security.powerauth.http.PowerAuthSignatureHttpHeader;
import com.wultra.security.powerauth.rest.api.model.request.EciesEncryptedRequest;
import com.wultra.security.powerauth.rest.api.model.response.EciesEncryptedResponse;
import com.wultra.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthUpgradeException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthSignatureInvalidException;
import com.wultra.security.powerauth.rest.api.spring.provider.PowerAuthAuthenticationProvider;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;

/**
 * Service implementing upgrade functionality.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@Service("upgradeServiceV3")
public class UpgradeService {

    private static final Logger logger = LoggerFactory.getLogger(UpgradeService.class);

    private final PowerAuthClient powerAuthClient;
    private final PowerAuthAuthenticationProvider authenticationProvider;
    private final HttpCustomizationService httpCustomizationService;

    /**
     * Service constructor.
     * @param powerAuthClient PowerAuth client.
     * @param authenticationProvider Authentication provider.
     * @param httpCustomizationService HTTP customization service.
     */
    @Autowired
    public UpgradeService(PowerAuthClient powerAuthClient, PowerAuthAuthenticationProvider authenticationProvider, HttpCustomizationService httpCustomizationService) {
        this.powerAuthClient = powerAuthClient;
        this.authenticationProvider = authenticationProvider;
        this.httpCustomizationService = httpCustomizationService;
    }

    /**
     * Start upgrade of activation to version 3.
     * @param request ECIES encrypted upgrade start request.
     * @param header PowerAuth encryption HTTP header.
     * @return ECIES encrypted upgrade activation response.
     * @throws PowerAuthUpgradeException In case upgrade start fails.
     */
    public EciesEncryptedResponse upgradeStart(EciesEncryptedRequest request, PowerAuthEncryptionHttpHeader header)
            throws PowerAuthUpgradeException {

        try {
            // Get ECIES headers
            final String activationId = header.getActivationId();
            final String applicationKey = header.getApplicationKey();

            // Start upgrade on PowerAuth server
            final StartUpgradeRequest upgradeRequest = new StartUpgradeRequest();
            upgradeRequest.setActivationId(activationId);
            upgradeRequest.setApplicationKey(applicationKey);
            upgradeRequest.setTemporaryKeyId(request.getTemporaryKeyId());
            upgradeRequest.setEphemeralPublicKey(request.getEphemeralPublicKey());
            upgradeRequest.setEncryptedData(request.getEncryptedData());
            upgradeRequest.setMac(request.getMac());
            upgradeRequest.setNonce(request.getNonce());
            upgradeRequest.setProtocolVersion(header.getVersion());
            upgradeRequest.setTimestamp(request.getTimestamp());
            final StartUpgradeResponse upgradeResponse = powerAuthClient.startUpgrade(
                    upgradeRequest,
                    httpCustomizationService.getQueryParams(),
                    httpCustomizationService.getHttpHeaders()
            );

            // Prepare a response
            final EciesEncryptedResponse response = new EciesEncryptedResponse();
            response.setMac(upgradeResponse.getMac());
            response.setEncryptedData(upgradeResponse.getEncryptedData());
            response.setNonce(upgradeResponse.getNonce());
            response.setTimestamp(upgradeResponse.getTimestamp());
            return response;
        } catch (Exception ex) {
            logger.warn("PowerAuth upgrade start failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthUpgradeException();
        }
    }

    /**
     * Commit upgrade of activation to version 3.
     * @param signatureHeader PowerAuth signature HTTP header.
     * @param httpServletRequest HTTP servlet request.
     * @return Commit upgrade response.
     * @throws PowerAuthAuthenticationException in case authentication fails.
     * @throws PowerAuthUpgradeException In case upgrade commit fails.
     */
    public Response upgradeCommit(String signatureHeader,
                                  HttpServletRequest httpServletRequest)
            throws PowerAuthAuthenticationException, PowerAuthUpgradeException {

        try {
            // Extract request body
            final byte[] requestBodyBytes = authenticationProvider.extractRequestBodyBytes(httpServletRequest);
            if (requestBodyBytes == null || requestBodyBytes.length == 0) {
                // Expected request body is {}, do not accept empty body
                logger.warn("Empty request body");
                throw new PowerAuthInvalidRequestException();
            }

            // Verify signature, force signature version during upgrade to version 3
            final List<PowerAuthSignatureTypes> allowedSignatureTypes = Collections.singletonList(PowerAuthSignatureTypes.POSSESSION);
            final PowerAuthApiAuthentication authentication = authenticationProvider.validateRequestSignatureWithActivationDetails("POST", requestBodyBytes, "/pa/upgrade/commit", signatureHeader, allowedSignatureTypes, 3);

            // In case signature verification fails, upgrade fails, too
            if (!authentication.getAuthenticationContext().isValid() || authentication.getActivationContext().getActivationId() == null) {
                logger.debug("Signature validation failed");
                throw new PowerAuthSignatureInvalidException();
            }

            // Get signature HTTP headers
            final String activationId = authentication.getActivationContext().getActivationId();
            final PowerAuthSignatureHttpHeader httpHeader = (PowerAuthSignatureHttpHeader) authentication.getHttpHeader();
            final String applicationKey = httpHeader.getApplicationKey();

            // Commit upgrade on PowerAuth server
            final CommitUpgradeRequest commitRequest = new CommitUpgradeRequest();
            commitRequest.setActivationId(activationId);
            commitRequest.setApplicationKey(applicationKey);
            final CommitUpgradeResponse upgradeResponse = powerAuthClient.commitUpgrade(
                    commitRequest,
                    httpCustomizationService.getQueryParams(),
                    httpCustomizationService.getHttpHeaders()
            );

            if (upgradeResponse.isCommitted()) {
                return new Response();
            } else {
                logger.debug("Upgrade commit failed");
                throw new PowerAuthUpgradeException();
            }
        } catch (PowerAuthAuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            logger.warn("PowerAuth upgrade commit failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthUpgradeException();
        }
    }
}
