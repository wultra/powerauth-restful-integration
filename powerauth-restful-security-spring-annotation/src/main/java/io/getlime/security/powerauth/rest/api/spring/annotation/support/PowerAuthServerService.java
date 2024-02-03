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
package io.getlime.security.powerauth.rest.api.spring.annotation.support;

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.ValidateTokenRequest;
import com.wultra.security.powerauth.client.model.request.VerifySignatureRequest;
import com.wultra.security.powerauth.client.model.response.ValidateTokenResponse;
import com.wultra.security.powerauth.client.model.response.VerifySignatureResponse;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthHttpHeader;
import io.getlime.security.powerauth.rest.api.spring.authentication.PowerAuthActivation;
import io.getlime.security.powerauth.rest.api.spring.authentication.impl.PowerAuthActivationImpl;
import io.getlime.security.powerauth.rest.api.spring.authentication.impl.PowerAuthApiAuthenticationImpl;
import io.getlime.security.powerauth.rest.api.spring.authentication.impl.PowerAuthSignatureAuthenticationImpl;
import io.getlime.security.powerauth.rest.api.spring.authentication.impl.PowerAuthTokenAuthenticationImpl;
import io.getlime.security.powerauth.rest.api.spring.converter.ActivationStatusConverter;
import io.getlime.security.powerauth.rest.api.spring.converter.SignatureTypeConverter;
import io.getlime.security.powerauth.rest.api.spring.model.ActivationStatus;
import io.getlime.security.powerauth.rest.api.spring.model.AuthenticationContext;
import io.getlime.security.powerauth.rest.api.spring.service.HttpCustomizationService;
import lombok.extern.slf4j.Slf4j;

import java.util.List;

/**
 * Service class for service based on PowerAuth Server API.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Slf4j
public class PowerAuthServerService implements PowerAuthService {

    private final PowerAuthClient powerAuthClient;
    private final HttpCustomizationService httpCustomizationService;
    private final ActivationStatusConverter activationStatusConverter;

    public PowerAuthServerService(PowerAuthClient powerAuthClient, HttpCustomizationService httpCustomizationService, ActivationStatusConverter activationStatusConverter) {
        this.powerAuthClient = powerAuthClient;
        this.httpCustomizationService = httpCustomizationService;
        this.activationStatusConverter = activationStatusConverter;
    }

    @Override
    public PowerAuthApiAuthenticationImpl validateSignature(PowerAuthSignatureAuthenticationImpl authentication) throws PowerAuthClientException {

        final SignatureTypeConverter converter = new SignatureTypeConverter();
        final SignatureType signatureType = converter.convertFrom(authentication.getSignatureType());
        if (signatureType == null) {
            return null;
        }

        final VerifySignatureRequest verifyRequest = new VerifySignatureRequest();
        verifyRequest.setActivationId(authentication.getActivationId());
        verifyRequest.setApplicationKey(authentication.getApplicationKey());
        verifyRequest.setSignature(authentication.getSignature());
        verifyRequest.setSignatureType(signatureType);
        verifyRequest.setSignatureVersion(authentication.getVersion());
        verifyRequest.setData(PowerAuthHttpBody.getSignatureBaseString(
                authentication.getHttpMethod(),
                authentication.getRequestUri(),
                authentication.getNonce(),
                authentication.getData()
        ));

        // In case forced signature version is specified, use it in the request.
        // This occurs when verifying signature during upgrade before upgrade is committed.
        if (authentication.getForcedSignatureVersion() != null) {
            verifyRequest.setForcedSignatureVersion(authentication.getForcedSignatureVersion().longValue());
        }

        final VerifySignatureResponse response = powerAuthClient.verifySignature(
                verifyRequest,
                httpCustomizationService.getQueryParams(),
                httpCustomizationService.getHttpHeaders()
        );
        final ActivationStatus activationStatus = activationStatusConverter.convertFrom(response.getActivationStatus());
        final AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setValid(response.isSignatureValid());
        authenticationContext.setRemainingAttempts(response.getRemainingAttempts() != null ? response.getRemainingAttempts().intValue() : null);
        authenticationContext.setSignatureType(response.getSignatureType() != null ? PowerAuthSignatureTypes.getEnumFromString(response.getSignatureType().name()) : null);
        final PowerAuthActivation activationContext = copyActivationAttributes(response.getActivationId(), response.getUserId(),
                activationStatus, response.getBlockedReason(),
                response.getActivationFlags(), authenticationContext, authentication.getVersion());
        return copyAuthenticationAttributes(response.getActivationId(), response.getUserId(),
                response.getApplicationId(), response.getApplicationRoles(), response.getActivationFlags(),
                authenticationContext, authentication.getVersion(), authentication.getHttpHeader(),
                activationContext);
    }

    @Override
    public PowerAuthApiAuthenticationImpl validateToken(PowerAuthTokenAuthenticationImpl authentication) throws PowerAuthClientException {
        final ValidateTokenRequest validateRequest = new ValidateTokenRequest();
        validateRequest.setTokenId(authentication.getTokenId());
        validateRequest.setTokenDigest(authentication.getTokenDigest());
        validateRequest.setNonce(authentication.getNonce());
        validateRequest.setTimestamp(Long.parseLong(authentication.getTimestamp()));
        validateRequest.setProtocolVersion(authentication.getVersion());

        final ValidateTokenResponse response = powerAuthClient.validateToken(
                validateRequest,
                httpCustomizationService.getQueryParams(),
                httpCustomizationService.getHttpHeaders()
        );

        final ActivationStatus activationStatus = activationStatusConverter.convertFrom(response.getActivationStatus());
        final AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setValid(response.isTokenValid());
        authenticationContext.setRemainingAttempts(null);
        authenticationContext.setSignatureType(response.getSignatureType() != null ? PowerAuthSignatureTypes.getEnumFromString(response.getSignatureType().name()) : null);
        final PowerAuthActivation activationContext = copyActivationAttributes(response.getActivationId(), response.getUserId(),
                activationStatus, response.getBlockedReason(),
                response.getActivationFlags(), authenticationContext, authentication.getVersion());
        return copyAuthenticationAttributes(response.getActivationId(), response.getUserId(),
                response.getApplicationId(), response.getApplicationRoles(), response.getActivationFlags(),
                authenticationContext, authentication.getVersion(), authentication.getHttpHeader(),
                activationContext);
    }


    /**
     * Prepare API initialized authentication object with provided authentication attributes.
     * @param activationId Activation ID.
     * @param userId User ID.
     * @param applicationId Application ID.
     * @param applicationRoles Application roles.
     * @param activationFlags Activation flags.
     * @param authenticationContext Authentication context.
     * @param version PowerAuth protocol version.
     * @param httpHeader Raw PowerAuth http header.
     * @param activationContext PowerAuth activation context.
     * @return Initialized instance of API authentication.
     */
    private PowerAuthApiAuthenticationImpl copyAuthenticationAttributes(String activationId, String userId, String applicationId, List<String> applicationRoles,
                                                                        List<String> activationFlags, AuthenticationContext authenticationContext,
                                                                        String version, PowerAuthHttpHeader httpHeader, PowerAuthActivation activationContext) {
        final PowerAuthApiAuthenticationImpl apiAuthentication = new PowerAuthApiAuthenticationImpl();
        apiAuthentication.setActivationId(activationId);
        apiAuthentication.setUserId(userId);
        apiAuthentication.setApplicationId(applicationId);
        apiAuthentication.setApplicationRoles(applicationRoles);
        apiAuthentication.setActivationFlags(activationFlags);
        apiAuthentication.setAuthenticationContext(authenticationContext);
        apiAuthentication.setAuthenticated(true);
        apiAuthentication.setVersion(version);
        apiAuthentication.setHttpHeader(httpHeader);
        apiAuthentication.setActivationContext(activationContext);
        return apiAuthentication;
    }

    /**
     * Prepare activation detail with provided attributes.
     * @param activationId Activation ID.
     * @param userId User ID.
     * @param activationStatus Activation status.
     * @param blockedReason Reason why activation was blocked.
     * @param activationFlags Activation flags.
     * @param authenticationContext Authentication context.
     * @param version PowerAuth protocol version.
     * @return Initialized instance of API authentication.
     */
    private PowerAuthActivationImpl copyActivationAttributes(String activationId, String userId, ActivationStatus activationStatus, String blockedReason,
                                                             List<String> activationFlags, AuthenticationContext authenticationContext, String version) {
        final PowerAuthActivationImpl activationContext = new PowerAuthActivationImpl();
        activationContext.setActivationId(activationId);
        activationContext.setUserId(userId);
        activationContext.setActivationStatus(activationStatus);
        activationContext.setBlockedReason(blockedReason);
        activationContext.setActivationFlags(activationFlags);
        activationContext.setAuthenticationContext(authenticationContext);
        activationContext.setVersion(version);
        return activationContext;
    }

}
