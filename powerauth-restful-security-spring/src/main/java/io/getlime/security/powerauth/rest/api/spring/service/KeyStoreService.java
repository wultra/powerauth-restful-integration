/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2024 Wultra s.r.o.
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
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.TemporaryPublicKeyRequest;
import com.wultra.security.powerauth.client.model.response.TemporaryPublicKeyResponse;
import io.getlime.security.powerauth.rest.api.model.request.TemporaryKeyRequest;
import io.getlime.security.powerauth.rest.api.model.response.TemporaryKeyResponse;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthTemporaryKeyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Key store service for obtaining temporary encryption keys.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service
public class KeyStoreService {

    private static final Logger logger = LoggerFactory.getLogger(KeyStoreService.class);

    private final PowerAuthClient powerAuthClient;
    private final HttpCustomizationService httpCustomizationService;

    /**
     * Default autowiring constructor.
     * @param powerAuthClient PowerAuth Client
     * @param httpCustomizationService Customization service.
     */
    @Autowired
    public KeyStoreService(PowerAuthClient powerAuthClient, HttpCustomizationService httpCustomizationService) {
        this.powerAuthClient = powerAuthClient;
        this.httpCustomizationService = httpCustomizationService;
    }

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
