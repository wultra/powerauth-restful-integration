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
package io.getlime.security.powerauth.rest.api.spring.controller.v3;

import io.getlime.core.rest.model.base.response.Response;
import io.getlime.powerauth.soap.v3.CommitUpgradeResponse;
import io.getlime.powerauth.soap.v3.StartUpgradeResponse;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.http.PowerAuthEncryptionHttpHeader;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.http.validator.InvalidPowerAuthHttpHeaderException;
import io.getlime.security.powerauth.http.validator.PowerAuthEncryptionHttpHeaderValidator;
import io.getlime.security.powerauth.http.validator.PowerAuthSignatureHttpHeaderValidator;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthUpgradeException;
import io.getlime.security.powerauth.rest.api.base.filter.PowerAuthRequestFilterBase;
import io.getlime.security.powerauth.rest.api.base.model.PowerAuthRequestBody;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import io.getlime.security.powerauth.rest.api.spring.provider.PowerAuthAuthenticationProvider;
import io.getlime.security.powerauth.soap.spring.client.PowerAuthServiceClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.List;

/**
 * Controller responsible for upgrade.
 *
 * <h5>PowerAuth protocol versions:</h5>
 * <ul>
 *     <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra
 */
@RestController
@RequestMapping("/pa/v3/upgrade")
public class UpgradeController {

    private static final Logger logger = LoggerFactory.getLogger(UpgradeController.class);

    private PowerAuthServiceClient powerAuthClient;
    private PowerAuthAuthenticationProvider authenticationProvider;

    @Autowired
    public void setPowerAuthClient(PowerAuthServiceClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @Autowired
    public void setAuthenticationProvider(PowerAuthAuthenticationProvider authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
    }

    /**
     * Start upgrade of activation to version 3.
     *
     * @param request ECIES encrypted request.
     * @param encryptionHeader Encryption HTTP header.
     * @return ECIES encrypted response.
     * @throws PowerAuthUpgradeException In case upgrade fails.
     */
    @RequestMapping(value = "start", method = RequestMethod.POST)
    public EciesEncryptedResponse upgradeStart(@RequestBody EciesEncryptedRequest request,
                                                 @RequestHeader(value = PowerAuthEncryptionHttpHeader.HEADER_NAME, defaultValue = "unknown") String encryptionHeader)
            throws PowerAuthUpgradeException {

        try {
            // Parse the encryption header
            PowerAuthEncryptionHttpHeader header = new PowerAuthEncryptionHttpHeader().fromValue(encryptionHeader);

            // Validate the encryption header
            try {
                PowerAuthEncryptionHttpHeaderValidator.validate(header);
            } catch (InvalidPowerAuthHttpHeaderException e) {
                throw new PowerAuthUpgradeException(e.getMessage());
            }

            if (!"3.0".equals(header.getVersion())) {
                logger.warn("Endpoint does not support PowerAuth protocol version {}", header.getVersion());
                throw new PowerAuthAuthenticationException();
            }

            // Fetch data from the request
            final String ephemeralPublicKey = request.getEphemeralPublicKey();
            final String encryptedData = request.getEncryptedData();
            final String mac = request.getMac();

            // Get ECIES headers
            final String activationId = header.getActivationId();
            final String applicationKey = header.getApplicationKey();

            // Start upgrade on PowerAuth server
            StartUpgradeResponse upgradeResponse = powerAuthClient.startUpgrade(activationId, applicationKey, ephemeralPublicKey, encryptedData, mac);

            // Prepare a response
            final EciesEncryptedResponse response = new EciesEncryptedResponse();
            response.setMac(upgradeResponse.getMac());
            response.setEncryptedData(upgradeResponse.getEncryptedData());
            return response;
        } catch (Exception ex) {
            logger.warn("PowerAuth upgrade start failed.", ex);
            throw new PowerAuthUpgradeException();
        }
    }

    /**
     * Commit upgrade of activation to version 3.
     *
     * @param signatureHeader PowerAuth signature HTTP header.
     * @return Response.
     * @throws PowerAuthAuthenticationException In case request signature is invalid.
     * @throws PowerAuthUpgradeException In case commit fails.
     */
    @RequestMapping(value = "commit", method = RequestMethod.POST)
    public Response upgradeCommit(@RequestHeader(value = PowerAuthSignatureHttpHeader.HEADER_NAME) String signatureHeader,
                                  HttpServletRequest httpServletRequest)
            throws PowerAuthAuthenticationException, PowerAuthUpgradeException {

        try {
            // Parse the signature header
            PowerAuthSignatureHttpHeader header = new PowerAuthSignatureHttpHeader().fromValue(signatureHeader);

            // Validate the signature header
            try {
                PowerAuthSignatureHttpHeaderValidator.validate(header);
            } catch (InvalidPowerAuthHttpHeaderException e) {
                throw new PowerAuthUpgradeException(e.getMessage());
            }

            if (!"3.0".equals(header.getVersion())) {
                logger.warn("Endpoint does not support PowerAuth protocol version {}", header.getVersion());
                throw new PowerAuthAuthenticationException();
            }

            // Extract request body
            PowerAuthRequestBody requestBody = ((PowerAuthRequestBody) httpServletRequest.getAttribute(PowerAuthRequestFilterBase.POWERAUTH_REQUEST_BODY));
            byte[] requestBodyBytes = requestBody.getRequestBytes();
            if (requestBodyBytes.length == 0) {
                // Expected request body is {}, do not accept empty body
                throw new PowerAuthAuthenticationException();
            }

            // Verify signature, force signature version during upgrade to version 3
            List<PowerAuthSignatureTypes> allowedSignatureTypes = Collections.singletonList(PowerAuthSignatureTypes.POSSESSION);
            PowerAuthApiAuthentication authentication = authenticationProvider.validateRequestSignature("POST", requestBodyBytes, "/pa/upgrade/commit", signatureHeader, allowedSignatureTypes, 3);

            // In case signature verification fails, upgrade fails, too
            if (authentication == null || authentication.getActivationId() == null) {
                throw new PowerAuthAuthenticationException();
            }

            // Get signature HTTP headers
            final String activationId = authentication.getActivationId();
            final PowerAuthSignatureHttpHeader httpHeader = (PowerAuthSignatureHttpHeader) authentication.getHttpHeader();
            final String applicationKey = httpHeader.getApplicationKey();

            // Commit upgrade on PowerAuth server
            CommitUpgradeResponse upgradeResponse = powerAuthClient.commitUpgrade(activationId, applicationKey);

            if (upgradeResponse.isCommitted()) {
                return new Response();
            } else {
                throw new PowerAuthUpgradeException();
            }
        } catch (PowerAuthAuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            logger.warn("PowerAuth upgrade commit failed.", ex);
            throw new PowerAuthUpgradeException();
        }
    }
}
