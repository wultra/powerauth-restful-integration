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
import com.wultra.security.powerauth.client.model.request.TemporaryPublicKeyRequest;
import com.wultra.security.powerauth.client.model.response.TemporaryPublicKeyResponse;
import com.wultra.security.powerauth.client.v4.PowerAuthClient;
import com.wultra.security.powerauth.rest.api.model.request.TemporaryKeyRequest;
import com.wultra.security.powerauth.rest.api.model.response.TemporaryKeyResponse;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthTemporaryKeyException;
import com.wultra.security.powerauth.rest.api.spring.service.HttpCustomizationService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Key store service for obtaining temporary encryption keys.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service("keyStoreServiceV4")
@AllArgsConstructor
@Slf4j
public class KeyStoreService {

    private final PowerAuthClient powerAuthClient;
    private final HttpCustomizationService httpCustomizationService;

    /**
     * Fetch a temporary public key with provided parameters.
     * @param request Temporary public key request.
     * @return Response with temporary public key.
     * @throws PowerAuthTemporaryKeyException In case internal API call fails.
     */
    public TemporaryKeyResponse fetchTemporaryKey(TemporaryKeyRequest request) throws PowerAuthTemporaryKeyException {
        try {
            final TemporaryPublicKeyRequest publicKeyRequest = new TemporaryPublicKeyRequest();
            publicKeyRequest.setJwt(request.getJwt());

            final TemporaryPublicKeyResponse temporaryPublicKeyResponse = powerAuthClient.fetchTemporaryPublicKey(
                    publicKeyRequest,
                    httpCustomizationService.getQueryParams(),
                    httpCustomizationService.getHttpHeaders()
            );

            final TemporaryKeyResponse response = new TemporaryKeyResponse();
            response.setJwt(temporaryPublicKeyResponse.getJwt());
            return response;
        } catch (PowerAuthClientException ex) {
            logger.warn("PowerAuth fetching temporary key failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthTemporaryKeyException();
        }
    }
}
