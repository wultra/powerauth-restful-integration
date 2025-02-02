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
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.request.CreateTokenRequest;
import com.wultra.security.powerauth.client.model.request.RemoveTokenRequest;
import com.wultra.security.powerauth.client.model.response.CreateTokenResponse;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import com.wultra.security.powerauth.http.PowerAuthSignatureHttpHeader;
import com.wultra.security.powerauth.rest.api.model.request.EciesEncryptedRequest;
import com.wultra.security.powerauth.rest.api.model.request.TokenRemoveRequest;
import com.wultra.security.powerauth.rest.api.model.response.EciesEncryptedResponse;
import com.wultra.security.powerauth.rest.api.model.response.TokenRemoveResponse;
import com.wultra.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import com.wultra.security.powerauth.rest.api.spring.converter.SignatureTypeConverter;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthSignatureTypeInvalidException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthTokenErrorException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Service implementing token functionality.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service("tokenServiceV3")
public class TokenService {

    private static final Logger logger = LoggerFactory.getLogger(TokenService.class);

    private final PowerAuthClient powerAuthClient;
    private final HttpCustomizationService httpCustomizationService;

    /**
     * Service constructor.
     * @param powerAuthClient PowerAuth client.
     * @param httpCustomizationService HTTP customization service.
     */
    @Autowired
    public TokenService(PowerAuthClient powerAuthClient, HttpCustomizationService httpCustomizationService) {
        this.powerAuthClient = powerAuthClient;
        this.httpCustomizationService = httpCustomizationService;
    }

    /**
     * Create token.
     *
     * @param request        ECIES encrypted create token request.
     * @param authentication PowerAuth API authentication object.
     * @return ECIES encrypted create token response.
     * @throws PowerAuthAuthenticationException In case token could not be created.
     */
    public EciesEncryptedResponse createToken(EciesEncryptedRequest request,
                                              PowerAuthApiAuthentication authentication)
            throws PowerAuthAuthenticationException {
        try {
            // Fetch activation ID and signature type
            final PowerAuthSignatureTypes signatureFactors = authentication.getAuthenticationContext().getSignatureType();

            // Prepare a signature type converter
            final SignatureTypeConverter converter = new SignatureTypeConverter();
            final SignatureType signatureType = converter.convertFrom(signatureFactors);
            if (signatureType == null) {
                logger.warn("Invalid signature type: {}", signatureFactors);
                throw new PowerAuthSignatureTypeInvalidException();
            }

            // Get ECIES headers
            final String activationId = authentication.getActivationContext().getActivationId();
            final PowerAuthSignatureHttpHeader httpHeader = (PowerAuthSignatureHttpHeader) authentication.getHttpHeader();
            final String applicationKey = httpHeader.getApplicationKey();

            // Create a token
            final CreateTokenRequest tokenRequest = new CreateTokenRequest();
            tokenRequest.setActivationId(activationId);
            tokenRequest.setApplicationKey(applicationKey);
            tokenRequest.setTemporaryKeyId(request.getTemporaryKeyId());
            tokenRequest.setEphemeralPublicKey(request.getEphemeralPublicKey());
            tokenRequest.setEncryptedData(request.getEncryptedData());
            tokenRequest.setMac(request.getMac());
            tokenRequest.setNonce(request.getNonce());
            tokenRequest.setSignatureType(signatureType);
            tokenRequest.setProtocolVersion(httpHeader.getVersion());
            tokenRequest.setTimestamp(request.getTimestamp());
            final CreateTokenResponse token = powerAuthClient.createToken(
                    tokenRequest,
                    httpCustomizationService.getQueryParams(),
                    httpCustomizationService.getHttpHeaders()
            );

            // Prepare a response
            final EciesEncryptedResponse response = new EciesEncryptedResponse();
            response.setMac(token.getMac());
            response.setEncryptedData(token.getEncryptedData());
            response.setNonce(token.getNonce());
            response.setTimestamp(token.getTimestamp());
            return response;
        } catch (Exception ex) {
            logger.warn("Creating PowerAuth token failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthTokenErrorException();
        }
    }

    /**
     * Remove token.
     *
     * @param request        Remove token request.
     * @param authentication PowerAuth API authentication object.
     * @return Remove token response.
     * @throws PowerAuthAuthenticationException In case authentication fails.
     */
    public TokenRemoveResponse removeToken(TokenRemoveRequest request, PowerAuthApiAuthentication authentication) throws PowerAuthAuthenticationException {
        try {
            // Fetch activation ID
            final String activationId = authentication.getActivationContext().getActivationId();

            // Fetch token ID from the request
            final String tokenId = request.getTokenId();

            // Remove a token, ignore response, since the endpoint should quietly return
            final RemoveTokenRequest removeRequest = new RemoveTokenRequest();
            removeRequest.setActivationId(activationId);
            removeRequest.setTokenId(tokenId);
            powerAuthClient.removeToken(
                    removeRequest,
                    httpCustomizationService.getQueryParams(),
                    httpCustomizationService.getHttpHeaders()
            );

            // Prepare a response
            final TokenRemoveResponse response = new TokenRemoveResponse();
            response.setTokenId(tokenId);
            return response;
        } catch (Exception ex) {
            logger.warn("Removing PowerAuth token failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthTokenErrorException();
        }
    }
}
