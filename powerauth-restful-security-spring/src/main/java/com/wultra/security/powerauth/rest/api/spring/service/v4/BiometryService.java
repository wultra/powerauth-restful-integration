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

import com.wultra.core.rest.model.base.response.Response;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.v4.AddBiometryRequest;
import com.wultra.security.powerauth.client.model.request.v4.RemoveBiometryRequest;
import com.wultra.security.powerauth.client.model.response.v4.AddBiometryResponse;
import com.wultra.security.powerauth.client.v4.PowerAuthClient;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.request.AeadEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import com.wultra.security.powerauth.http.PowerAuthAuthorizationHttpHeader;
import com.wultra.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthBiometryException;
import com.wultra.security.powerauth.rest.api.spring.service.HttpCustomizationService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Service for setting up biometry.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service("biometryServiceV4")
@AllArgsConstructor
@Slf4j
public class BiometryService {

    private final PowerAuthClient powerAuthClient;
    private final HttpCustomizationService httpCustomizationService;

    /**
     * Set up biometry.
     * @param request Encrypted request.
     * @param auth PowerAuth API authentication.
     * @return Encrypted response.
     * @throws PowerAuthBiometryException In case internal API call fails.
     */
    public AeadEncryptedResponse addBiometry(AeadEncryptedRequest request, PowerAuthApiAuthentication auth) throws PowerAuthBiometryException {
        try {
            final String activationId = auth.getActivationContext().getActivationId();
            final PowerAuthAuthorizationHttpHeader httpHeader = (PowerAuthAuthorizationHttpHeader) auth.getHttpHeader();
            final String applicationKey = httpHeader.getApplicationKey();
            final String protocolVersion = httpHeader.getVersion();
            final AddBiometryRequest addBiometryRequest = convertAddBiometryRequest(request, activationId, applicationKey, protocolVersion);
            final AddBiometryResponse addBiometryResponse = powerAuthClient.addBiometry(
                    addBiometryRequest,
                    httpCustomizationService.getQueryParams(),
                    httpCustomizationService.getHttpHeaders()
            );

            final AeadEncryptedResponse response = new AeadEncryptedResponse();
            response.setEncryptedData(addBiometryResponse.getEncryptedData());
            response.setTimestamp(addBiometryResponse.getTimestamp());
            return response;
        } catch (PowerAuthClientException ex) {
            logger.warn("PowerAuth biometry setup failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthBiometryException();
        }
    }

    /**
     * Remove biometry.
     * @param activationId Activation identifier.
     * @return Shared secret response.
     * @throws PowerAuthBiometryException In case internal API call fails.
     */
    public Response removeBiometry(String activationId) throws PowerAuthBiometryException {
        try {
            final RemoveBiometryRequest removeBiometryRequest = new RemoveBiometryRequest();
            removeBiometryRequest.setActivationId(activationId);
            return powerAuthClient.removeBiometry(
                    removeBiometryRequest,
                    httpCustomizationService.getQueryParams(),
                    httpCustomizationService.getHttpHeaders()
            );
        } catch (PowerAuthClientException ex) {
            logger.warn("PowerAuth biometry remove failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthBiometryException();
        }
    }

    private static AddBiometryRequest convertAddBiometryRequest(AeadEncryptedRequest request, String activationId, String applicationKey, String protocolVersion) {
        final AddBiometryRequest addBiometryRequest = new AddBiometryRequest();
        addBiometryRequest.setActivationId(activationId);
        addBiometryRequest.setApplicationKey(applicationKey);
        addBiometryRequest.setTemporaryKeyId(request.getTemporaryKeyId());
        addBiometryRequest.setNonce(request.getNonce());
        addBiometryRequest.setEncryptedData(request.getEncryptedData());
        addBiometryRequest.setProtocolVersion(protocolVersion);
        addBiometryRequest.setTimestamp(request.getTimestamp());
        return addBiometryRequest;
    }

}
