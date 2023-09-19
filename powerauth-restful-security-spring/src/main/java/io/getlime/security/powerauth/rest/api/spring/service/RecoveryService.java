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
package io.getlime.security.powerauth.rest.api.spring.service;

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.request.ConfirmRecoveryCodeRequest;
import com.wultra.security.powerauth.client.model.response.ConfirmRecoveryCodeResponse;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.rest.api.model.request.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.EciesEncryptedResponse;
import io.getlime.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthRecoveryConfirmationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Service implementing recovery functionality.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service
public class RecoveryService {

    private static final Logger logger = LoggerFactory.getLogger(RecoveryService.class);

    private final PowerAuthClient powerAuthClient;
    private final HttpCustomizationService httpCustomizationService;

    /**
     * Controller constructor.
     * @param powerAuthClient PowerAuth client.
     * @param httpCustomizationService HTTP customization service.
     */
    @Autowired
    public RecoveryService(PowerAuthClient powerAuthClient, HttpCustomizationService httpCustomizationService) {
        this.powerAuthClient = powerAuthClient;
        this.httpCustomizationService = httpCustomizationService;
    }

    /**
     * Confirm recovery code.
     * @param request ECIES encrypted request.
     * @param authentication PowerAuth API authentication object.
     * @return ECIES encrypted response.
     * @throws PowerAuthAuthenticationException In case confirm recovery fails.
     */
    public EciesEncryptedResponse confirmRecoveryCode(EciesEncryptedRequest request,
                                                      PowerAuthApiAuthentication authentication) throws PowerAuthAuthenticationException {
        try {
            final String activationId = authentication.getActivationContext().getActivationId();
            final PowerAuthSignatureHttpHeader httpHeader = (PowerAuthSignatureHttpHeader) authentication.getHttpHeader();
            final String applicationKey = httpHeader.getApplicationKey();
            if (activationId == null || applicationKey == null) {
                logger.warn("PowerAuth confirm recovery failed because of invalid request");
                throw new PowerAuthInvalidRequestException();
            }
            final ConfirmRecoveryCodeRequest confirmRequest = new ConfirmRecoveryCodeRequest();
            confirmRequest.setActivationId(activationId);
            confirmRequest.setApplicationKey(applicationKey);
            confirmRequest.setEphemeralPublicKey(request.getEphemeralPublicKey());
            confirmRequest.setEncryptedData(request.getEncryptedData());
            confirmRequest.setMac(request.getMac());
            confirmRequest.setNonce(request.getNonce());
            confirmRequest.setProtocolVersion(httpHeader.getVersion());
            confirmRequest.setTimestamp(request.getTimestamp());
            final ConfirmRecoveryCodeResponse paResponse = powerAuthClient.confirmRecoveryCode(
                    confirmRequest,
                    httpCustomizationService.getQueryParams(),
                    httpCustomizationService.getHttpHeaders()
            );
            if (!paResponse.getActivationId().equals(activationId)) {
                logger.warn("PowerAuth confirm recovery failed because of invalid activation ID in response");
                throw new PowerAuthInvalidRequestException();
            }
            return new EciesEncryptedResponse(
                    paResponse.getEncryptedData(),
                    paResponse.getMac(),
                    paResponse.getNonce(),
                    paResponse.getTimestamp());
        } catch (Exception ex) {
            logger.warn("PowerAuth confirm recovery failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthRecoveryConfirmationException();
        }
    }
}
