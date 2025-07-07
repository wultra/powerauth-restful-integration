/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2025 Wultra s.r.o.
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
package com.wultra.security.powerauth.rest.api.spring.service.v4;

import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.v4.ChangePasswordRequest;
import com.wultra.security.powerauth.client.model.response.v4.ChangePasswordResponse;
import com.wultra.security.powerauth.client.v4.PowerAuthClient;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.request.AeadEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import com.wultra.security.powerauth.http.PowerAuthAuthorizationHttpHeader;
import com.wultra.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthPasswordException;
import com.wultra.security.powerauth.rest.api.spring.service.HttpCustomizationService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Service for changing password for the knowledge factor.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service("passwordServiceV4")
@AllArgsConstructor
@Slf4j
public class PasswordService {

    private final PowerAuthClient powerAuthClient;
    private final HttpCustomizationService httpCustomizationService;

    /**
     * Change the password.
     * @param request Encrypted request.
     * @param auth PowerAuth API authentication.
     * @return Encrypted response.
     * @throws PowerAuthPasswordException In case internal API call fails.
     */
    public AeadEncryptedResponse changePassword(AeadEncryptedRequest request, PowerAuthApiAuthentication auth) throws PowerAuthPasswordException {
        try {
            final String activationId = auth.getActivationContext().getActivationId();
            final PowerAuthAuthorizationHttpHeader httpHeader = (PowerAuthAuthorizationHttpHeader) auth.getHttpHeader();
            final String applicationKey = httpHeader.getApplicationKey();
            final String protocolVersion = httpHeader.getVersion();
            final ChangePasswordRequest changePasswordRequest = convertChangePasswordRequest(request, activationId, applicationKey, protocolVersion);
            final ChangePasswordResponse changePasswordResponse = powerAuthClient.changePassword(
                    changePasswordRequest,
                    httpCustomizationService.getQueryParams(),
                    httpCustomizationService.getHttpHeaders()
            );

            final AeadEncryptedResponse response = new AeadEncryptedResponse();
            response.setEncryptedData(changePasswordResponse.getEncryptedData());
            response.setTimestamp(changePasswordResponse.getTimestamp());
            return response;
        } catch (PowerAuthClientException ex) {
            logger.warn("PowerAuth changing password failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthPasswordException();
        }
    }

    private static ChangePasswordRequest convertChangePasswordRequest(AeadEncryptedRequest request, String activationId, String applicationKey, String protocolVersion)  {
        final ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
        changePasswordRequest.setActivationId(activationId);
        changePasswordRequest.setApplicationKey(applicationKey);
        changePasswordRequest.setTemporaryKeyId(request.getTemporaryKeyId());
        changePasswordRequest.setNonce(request.getNonce());
        changePasswordRequest.setEncryptedData(request.getEncryptedData());
        changePasswordRequest.setProtocolVersion(protocolVersion);
        changePasswordRequest.setTimestamp(request.getTimestamp());
        return changePasswordRequest;
    }

}
