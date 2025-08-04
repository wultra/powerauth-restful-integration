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

import com.wultra.security.powerauth.client.model.enumeration.v4.AuthenticationCodeType;
import com.wultra.security.powerauth.client.model.request.RemoveTokenRequest;
import com.wultra.security.powerauth.client.model.request.v4.CreateTokenRequest;
import com.wultra.security.powerauth.client.model.response.v4.CreateTokenResponse;
import com.wultra.security.powerauth.client.v4.PowerAuthClient;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.request.AeadEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.response.AeadEncryptedResponse;
import com.wultra.security.powerauth.http.PowerAuthAuthorizationHttpHeader;
import com.wultra.security.powerauth.rest.api.model.request.TokenRemoveRequest;
import com.wultra.security.powerauth.rest.api.model.response.TokenRemoveResponse;
import com.wultra.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import com.wultra.security.powerauth.rest.api.spring.converter.AuthenticationCodeTypeConverter;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthCodeTypeInvalidException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthTokenErrorException;
import com.wultra.security.powerauth.rest.api.spring.service.HttpCustomizationService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Service implementing token functionality.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>4.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service("tokenServiceV4")
@Slf4j
@AllArgsConstructor
public class TokenService {

    private final PowerAuthClient powerAuthClient;
    private final HttpCustomizationService httpCustomizationService;

    /**
     * Create token.
     *
     * @param request        AEAD encrypted create token request.
     * @param authentication PowerAuth API authentication object.
     * @return AEAD encrypted create token response.
     * @throws PowerAuthAuthenticationException In case token could not be created.
     */
    public AeadEncryptedResponse createToken(AeadEncryptedRequest request,
                                             PowerAuthApiAuthentication authentication)
            throws PowerAuthAuthenticationException {
        try {
            // Fetch activation ID and authentication code type
            final PowerAuthCodeType authenticationCodeTypeRequest = authentication.getAuthenticationContext().getAuthenticationCodeType();

            // Prepare an authentication code type converter
            final AuthenticationCodeTypeConverter converter = new AuthenticationCodeTypeConverter();
            final AuthenticationCodeType authenticationCodeType = converter.convertFrom(authenticationCodeTypeRequest);
            if (authenticationCodeType == null) {
                logger.warn("Invalid authentication code type: {}", authenticationCodeTypeRequest);
                throw new PowerAuthCodeTypeInvalidException();
            }

            // Get AEAD headers
            final String activationId = authentication.getActivationContext().getActivationId();
            final PowerAuthAuthorizationHttpHeader httpHeader = (PowerAuthAuthorizationHttpHeader) authentication.getHttpHeader();
            final String applicationKey = httpHeader.getApplicationKey();

            // Create a token
            final CreateTokenRequest tokenRequest = new CreateTokenRequest();
            tokenRequest.setActivationId(activationId);
            tokenRequest.setApplicationKey(applicationKey);
            tokenRequest.setTemporaryKeyId(request.getTemporaryKeyId());
            tokenRequest.setEncryptedData(request.getEncryptedData());
            tokenRequest.setNonce(request.getNonce());
            tokenRequest.setAuthenticationCodeType(authenticationCodeType);
            tokenRequest.setProtocolVersion(httpHeader.getVersion());
            tokenRequest.setTimestamp(request.getTimestamp());
            final CreateTokenResponse token = powerAuthClient.createToken(
                    tokenRequest,
                    httpCustomizationService.getQueryParams(),
                    httpCustomizationService.getHttpHeaders()
            );

            // Prepare a response
            final AeadEncryptedResponse response = new AeadEncryptedResponse();
            response.setEncryptedData(token.getEncryptedData());
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
