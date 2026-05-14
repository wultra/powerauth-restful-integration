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
package com.wultra.security.powerauth.rest.api.spring.provider;

import com.wultra.security.powerauth.client.model.enumeration.v4.AuthenticationCodeType;
import com.wultra.security.powerauth.client.model.request.v4.VerifyAuthenticationRequest;
import com.wultra.security.powerauth.client.model.response.v4.VerifyAuthenticationResponse;
import com.wultra.security.powerauth.client.model.enumeration.v3.SignatureType;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.ValidateTokenRequest;
import com.wultra.security.powerauth.client.model.request.v3.VerifySignatureRequest;
import com.wultra.security.powerauth.client.model.response.v3.VerifySignatureResponse;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.http.PowerAuthHttpBody;
import com.wultra.security.powerauth.http.PowerAuthHttpHeader;
import com.wultra.security.powerauth.http.PowerAuthAuthorizationHttpHeader;
import com.wultra.security.powerauth.http.PowerAuthTokenHttpHeader;
import com.wultra.security.powerauth.http.validator.InvalidPowerAuthHttpHeaderException;
import com.wultra.security.powerauth.http.validator.PowerAuthAuthorizationHttpHeaderValidator;
import com.wultra.security.powerauth.http.validator.PowerAuthTokenHttpHeaderValidator;
import com.wultra.security.powerauth.rest.api.spring.authentication.PowerAuthActivation;
import com.wultra.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import com.wultra.security.powerauth.rest.api.spring.authentication.impl.*;
import com.wultra.security.powerauth.rest.api.spring.converter.ActivationStatusConverter;
import com.wultra.security.powerauth.rest.api.spring.converter.AuthenticationCodeTypeConverter;
import com.wultra.security.powerauth.rest.api.spring.converter.SignatureTypeConverter;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthHeaderMissingException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthCodeInvalidException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthCodeTypeInvalidException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthTokenInvalidException;
import com.wultra.security.powerauth.rest.api.spring.model.ActivationStatus;
import com.wultra.security.powerauth.rest.api.spring.model.AuthenticationContext;
import com.wultra.security.powerauth.rest.api.spring.service.HttpCustomizationService;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.List;

/**
 * Implementation of PowerAuth authentication provider.
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
@Component
public class PowerAuthAuthenticationProvider extends PowerAuthAuthenticationProviderBase {

    private static final Logger logger = LoggerFactory.getLogger(PowerAuthAuthenticationProvider.class);

    private final com.wultra.security.powerauth.client.v3.PowerAuthClient powerAuthClientV3;
    private final com.wultra.security.powerauth.client.v4.PowerAuthClient powerAuthClientV4;
    private final ActivationStatusConverter activationStatusConverter;
    private final HttpCustomizationService httpCustomizationService;

    /**
     * Provider constructor.
     * @param powerAuthClientV3 PowerAuth client (V3).
     * @param powerAuthClientV4 PowerAuth client (V4).
     * @param activationStatusConverter Activation status converter.
     * @param httpCustomizationService HTTP customization service.
     */
    @Autowired
    public PowerAuthAuthenticationProvider(com.wultra.security.powerauth.client.v3.PowerAuthClient powerAuthClientV3, com.wultra.security.powerauth.client.v4.PowerAuthClient powerAuthClientV4, ActivationStatusConverter activationStatusConverter, HttpCustomizationService httpCustomizationService) {
        this.powerAuthClientV3 = powerAuthClientV3;
        this.powerAuthClientV4 = powerAuthClientV4;
        this.activationStatusConverter = activationStatusConverter;
        this.httpCustomizationService = httpCustomizationService;
    }

    /**
     * Authenticate user using the provided authentication.
     *
     * @param authentication Authentication used to verify the user.
     * @return Authentication with the authenticated user details.
     * @throws AuthenticationException In case authentication fails.
     */
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // Handle signature based authentications (V3)
        if (authentication instanceof PowerAuthSignatureAuthenticationImpl signatureAuthentication) {
            return authenticateSignatureRequest(signatureAuthentication);
        }
        // Handle authentication code based authentications (V4)
        if (authentication instanceof PowerAuthCodeAuthenticationImpl codeAuthentication) {
            return authenticateCodeRequest(codeAuthentication);
        }
        // Handle basic token-based authentications
        else if (authentication instanceof PowerAuthTokenAuthenticationImpl tokenAuthentication) {
            return switch (tokenAuthentication.getVersion()) {
                case "3.0", "3.1", "3.2", "3.3" -> authenticateTokenRequestV3(tokenAuthentication);
                case "4.0" -> authenticateTokenRequestV4(tokenAuthentication);
                default -> null;
            };
        }
        // Return null in case unknown authentication type is provided
        return null;
    }

    private PowerAuthApiAuthenticationImpl authenticateSignatureRequest(PowerAuthSignatureAuthenticationImpl authentication) {
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
        verifyRequest.setData(PowerAuthHttpBody.getAuthenticationBaseString(
                authentication.getHttpMethod(),
                authentication.getRequestUri(),
                authentication.getNonce(),
                authentication.getData()
        ));

        // In case forced signature version is specified, use it in the request.
        // This occurs when verifying signature during upgrade before upgrade is committed.
        if (authentication.getForcedSignatureVersion() != null) {
            verifyRequest.setForcedSignatureVersion(authentication.getForcedSignatureVersion());
        }

        final VerifySignatureResponse response;
        try {
            response = powerAuthClientV3.verifySignature(
                    verifyRequest,
                    httpCustomizationService.getQueryParams(),
                    httpCustomizationService.getHttpHeaders()
            );
        } catch (PowerAuthClientException ex) {
            logger.warn("Signature validation failed, error: {}", ex.getMessage());
            logger.debug("Error details", ex);
            return null;
        }
        final ActivationStatus activationStatus = activationStatusConverter.convert(response.getActivationStatus());
        final AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setValid(response.isSignatureValid());
        authenticationContext.setRemainingAttempts(response.getRemainingAttempts() != null ? response.getRemainingAttempts().intValue() : null);
        authenticationContext.setAuthenticationCodeType(response.getSignatureType() != null ? PowerAuthCodeType.getEnumFromString(response.getSignatureType().name()) : null);
        final PowerAuthActivation activationContext = copyActivationAttributes(response.getActivationId(), response.getUserId(),
                activationStatus, response.getBlockedReason(),
                response.getActivationFlags(), authenticationContext, authentication.getVersion());
        return copyAuthenticationAttributes(response.getActivationId(), response.getUserId(),
                response.getApplicationId(), response.getApplicationRoles(), response.getActivationFlags(),
                authenticationContext, authentication.getVersion(), authentication.getHttpHeader(),
                activationContext);
    }

    private PowerAuthApiAuthenticationImpl authenticateCodeRequest(PowerAuthCodeAuthenticationImpl authentication) {
        final AuthenticationCodeTypeConverter converter = new AuthenticationCodeTypeConverter();
        final AuthenticationCodeType authenticationCodeType = converter.convertFrom(authentication.getAuthenticationCodeType());
        if (authenticationCodeType == null) {
            return null;
        }
        final VerifyAuthenticationRequest verifyRequest = new VerifyAuthenticationRequest();
        verifyRequest.setActivationId(authentication.getActivationId());
        verifyRequest.setApplicationKey(authentication.getApplicationKey());
        verifyRequest.setAuthenticationCode(authentication.getAuthenticationCode());
        verifyRequest.setAuthenticationCodeType(authenticationCodeType);
        verifyRequest.setAuthenticationVersion(authentication.getVersion());
        verifyRequest.setData(PowerAuthHttpBody.getAuthenticationBaseString(
                authentication.getHttpMethod(),
                authentication.getRequestUri(),
                authentication.getNonce(),
                authentication.getData()
        ));
        verifyRequest.setAllowedStates(authentication.getAllowedStates().stream()
                        .map(activationStatusConverter::convert)
                        .toList()
        );

        final VerifyAuthenticationResponse response;
        try {
            response = powerAuthClientV4.verifyAuthentication(
                    verifyRequest,
                    httpCustomizationService.getQueryParams(),
                    httpCustomizationService.getHttpHeaders()
            );
        } catch (PowerAuthClientException ex) {
            logger.warn("Authentication code validation failed, error: {}", ex.getMessage());
            logger.debug("Error details", ex);
            return null;
        }
        final ActivationStatus activationStatus = activationStatusConverter.convert(response.getActivationStatus());
        final AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setValid(response.isAuthenticationValid());
        authenticationContext.setRemainingAttempts(response.getRemainingAttempts() != null ? response.getRemainingAttempts().intValue() : null);
        authenticationContext.setAuthenticationCodeType(response.getAuthenticationCodeType() != null ? PowerAuthCodeType.getEnumFromString(response.getAuthenticationCodeType().name()) : null);
        final PowerAuthActivation activationContext = copyActivationAttributes(response.getActivationId(), response.getUserId(),
                activationStatus, response.getBlockedReason(),
                response.getActivationFlags(), authenticationContext, authentication.getVersion());
        return copyAuthenticationAttributes(response.getActivationId(), response.getUserId(),
                response.getApplicationId(), response.getApplicationRoles(), response.getActivationFlags(),
                authenticationContext, authentication.getVersion(), authentication.getHttpHeader(),
                activationContext);
    }

    /**
     * Validate basic token-based authentication (V3).
     *
     * @param authentication Token based authentication object.
     * @return API authentication object in case of successful authentication, null otherwise.
     */
    private PowerAuthApiAuthenticationImpl authenticateTokenRequestV3(PowerAuthTokenAuthenticationImpl authentication) {
        try {
            final ValidateTokenRequest validateRequest = new ValidateTokenRequest();
            validateRequest.setTokenId(authentication.getTokenId());
            validateRequest.setTokenDigest(authentication.getTokenDigest());
            validateRequest.setNonce(authentication.getNonce());
            validateRequest.setTimestamp(Long.parseLong(authentication.getTimestamp()));
            validateRequest.setProtocolVersion(authentication.getVersion());

            final com.wultra.security.powerauth.client.model.response.v3.ValidateTokenResponse response = powerAuthClientV3.validateToken(
                    validateRequest,
                    httpCustomizationService.getQueryParams(),
                    httpCustomizationService.getHttpHeaders()
            );

            final ActivationStatus activationStatus = activationStatusConverter.convert(response.getActivationStatus());
            final AuthenticationContext authenticationContext = new AuthenticationContext();
            authenticationContext.setValid(response.isTokenValid());
            authenticationContext.setRemainingAttempts(null);
            authenticationContext.setAuthenticationCodeType(response.getSignatureType() != null ? PowerAuthCodeType.getEnumFromString(response.getSignatureType().name()) : null);
            final PowerAuthActivation activationContext = copyActivationAttributes(response.getActivationId(), response.getUserId(),
                    activationStatus, response.getBlockedReason(),
                    response.getActivationFlags(), authenticationContext, authentication.getVersion());
            return copyAuthenticationAttributes(response.getActivationId(), response.getUserId(),
                    response.getApplicationId(), response.getApplicationRoles(), response.getActivationFlags(),
                    authenticationContext, authentication.getVersion(), authentication.getHttpHeader(),
                    activationContext);
        } catch (NumberFormatException ex) {
            logger.warn("Invalid timestamp format, error: {}", ex.getMessage());
            logger.debug("Error details", ex);
            return null;
        } catch (Exception ex) {
            logger.warn("Token validation failed, error: {}", ex.getMessage());
            logger.debug("Error details", ex);
            return null;
        }
    }

    /**
     * Validate basic token-based authentication (V4).
     *
     * @param authentication Token based authentication object.
     * @return API authentication object in case of successful authentication, null otherwise.
     */
    private PowerAuthApiAuthenticationImpl authenticateTokenRequestV4(PowerAuthTokenAuthenticationImpl authentication) {
        try {
            final ValidateTokenRequest validateRequest = new ValidateTokenRequest();
            validateRequest.setTokenId(authentication.getTokenId());
            validateRequest.setTokenDigest(authentication.getTokenDigest());
            validateRequest.setNonce(authentication.getNonce());
            validateRequest.setTimestamp(Long.parseLong(authentication.getTimestamp()));
            validateRequest.setProtocolVersion(authentication.getVersion());

            final com.wultra.security.powerauth.client.model.response.v4.ValidateTokenResponse response = powerAuthClientV4.validateToken(
                    validateRequest,
                    httpCustomizationService.getQueryParams(),
                    httpCustomizationService.getHttpHeaders()
            );

            final ActivationStatus activationStatus = activationStatusConverter.convert(response.getActivationStatus());
            final AuthenticationContext authenticationContext = new AuthenticationContext();
            authenticationContext.setValid(response.isTokenValid());
            authenticationContext.setRemainingAttempts(null);
            authenticationContext.setAuthenticationCodeType(response.getAuthenticationCodeType() != null ? PowerAuthCodeType.getEnumFromString(response.getAuthenticationCodeType().name()) : null);
            final PowerAuthActivation activationContext = copyActivationAttributes(response.getActivationId(), response.getUserId(),
                    activationStatus, response.getBlockedReason(),
                    response.getActivationFlags(), authenticationContext, authentication.getVersion());
            return copyAuthenticationAttributes(response.getActivationId(), response.getUserId(),
                    response.getApplicationId(), response.getApplicationRoles(), response.getActivationFlags(),
                    authenticationContext, authentication.getVersion(), authentication.getHttpHeader(),
                    activationContext);
        } catch (NumberFormatException ex) {
            logger.warn("Invalid timestamp format, error: {}", ex.getMessage());
            logger.debug("Error details", ex);
            return null;
        } catch (Exception ex) {
            logger.warn("Token validation failed, error: {}", ex.getMessage());
            logger.debug("Error details", ex);
            return null;
        }
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
        apiAuthentication.setAuthenticated(authenticationContext.isValid());
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

    /**
     * Validate the authentication from the PowerAuth HTTP header against the provided HTTP method, request body and URI identifier.
     * Make sure to accept only allowed authentication code types.
     * @param httpMethod HTTP method (GET, POST, ...)
     * @param httpBody Body of the HTTP request.
     * @param requestUriIdentifier Request URI identifier.
     * @param httpAuthorizationHeader PowerAuth HTTP authorization header.
     * @param allowedAuthenticationCodeTypes Allowed authentication code types.
     * @return Instance of a PowerAuthApiAuthenticationImpl on successful authorization.
     * @throws PowerAuthAuthenticationException In case authorization fails, exception is raised.
     */
    public PowerAuthApiAuthentication validateRequestAuthentication(
            @Nonnull String httpMethod,
            @Nullable byte[] httpBody,
            @Nonnull String requestUriIdentifier,
            @Nonnull String httpAuthorizationHeader,
            @Nonnull List<PowerAuthCodeType> allowedAuthenticationCodeTypes,
            @Nonnull List<ActivationStatus> allowedStates
    ) throws PowerAuthAuthenticationException {
        final PowerAuthApiAuthentication apiAuthentication = validateRequestAuthenticationWithActivationDetails(httpMethod, httpBody, requestUriIdentifier, httpAuthorizationHeader, allowedAuthenticationCodeTypes, allowedStates);
        if (!apiAuthentication.getAuthenticationContext().isValid()) {
            // Traditionally, failed authentication returns null value for PowerAuthApiAuthentication
            return null;
        }
       return apiAuthentication;
    }

    @Override
    public @Nonnull PowerAuthApiAuthentication validateRequestAuthenticationWithActivationDetails(@Nonnull String httpMethod, @Nullable byte[] httpBody, @Nonnull String requestUriIdentifier, @Nonnull String httpAuthorizationHeader, @Nonnull List<PowerAuthCodeType> allowedAuthenticationCodeTypes, @Nonnull List<ActivationStatus> allowedStates) throws PowerAuthAuthenticationException {
        // Check for HTTP PowerAuth authorization header
        if (httpAuthorizationHeader.equals("undefined")) {
            logger.warn("Authorization HTTP header is missing");
            throw new PowerAuthHeaderMissingException();
        }

        // Parse HTTP header
        final PowerAuthAuthorizationHttpHeader header = new PowerAuthAuthorizationHttpHeader().fromValue(httpAuthorizationHeader);

        // Validate the header
        try {
            PowerAuthAuthorizationHttpHeaderValidator.validate(header);
        } catch (InvalidPowerAuthHttpHeaderException ex) {
            logger.warn("Authorization HTTP header validation failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthCodeInvalidException();
        }

        // Check if the authentication code type is allowed
        final PowerAuthCodeType expectedAuthCodeType = PowerAuthCodeType.getEnumFromString(header.getAuthCodeType());
        if (expectedAuthCodeType == null || !allowedAuthenticationCodeTypes.contains(expectedAuthCodeType)) {
            logger.warn("Invalid authentication code type: {}", expectedAuthCodeType);
            throw new PowerAuthCodeTypeInvalidException();
        }

        final PowerAuthApiAuthentication auth;
        switch (header.getVersion()) {
            case "3.0", "3.1", "3.2", "3.3" -> {
                // Configure PowerAuth authentication object
                final PowerAuthSignatureAuthenticationImpl powerAuthAuthentication = new PowerAuthSignatureAuthenticationImpl();
                powerAuthAuthentication.setActivationId(header.getActivationId());
                powerAuthAuthentication.setApplicationKey(header.getApplicationKey());
                powerAuthAuthentication.setNonce(Base64.getDecoder().decode(header.getNonce()));
                powerAuthAuthentication.setSignatureType(header.getAuthCodeType());
                powerAuthAuthentication.setSignature(header.getAuthCode());
                powerAuthAuthentication.setHttpMethod(httpMethod);
                powerAuthAuthentication.setRequestUri(requestUriIdentifier);
                powerAuthAuthentication.setData(httpBody);
                powerAuthAuthentication.setVersion(header.getVersion());
                powerAuthAuthentication.setHttpHeader(header);

                // Call the authentication based on signature authentication object
                auth = (PowerAuthApiAuthentication) this.authenticate(powerAuthAuthentication);
            }
            default -> {
                // Configure PowerAuth authentication object
                final PowerAuthCodeAuthenticationImpl powerAuthAuthentication = new PowerAuthCodeAuthenticationImpl();
                powerAuthAuthentication.setActivationId(header.getActivationId());
                powerAuthAuthentication.setApplicationKey(header.getApplicationKey());
                powerAuthAuthentication.setNonce(Base64.getDecoder().decode(header.getNonce()));
                powerAuthAuthentication.setAuthenticationCodeType(header.getAuthCodeType());
                powerAuthAuthentication.setAuthenticationCode(header.getAuthCode());
                powerAuthAuthentication.setHttpMethod(httpMethod);
                powerAuthAuthentication.setRequestUri(requestUriIdentifier);
                powerAuthAuthentication.setData(httpBody);
                powerAuthAuthentication.setVersion(header.getVersion());
                powerAuthAuthentication.setHttpHeader(header);
                powerAuthAuthentication.setAllowedStates(allowedStates);

                // Call the authentication based on authentication code validation object
                auth = (PowerAuthApiAuthentication) this.authenticate(powerAuthAuthentication);
            }
        }



        // In case authentication is null, throw PowerAuth exception
        if (auth == null) {
            logger.debug("Authentication code validation failed");
            throw new PowerAuthCodeInvalidException();
        }

        return auth;
    }

    /**
     * Validate token header for simple token-based authentication.
     *
     * @param tokenHeader Token header.
     * @param allowedAuthenticationCodeTypes Allowed authentication code types.
     * @return Authentication object in case authentication is correctly obtained.
     * @throws PowerAuthAuthenticationException In case of authentication failure.
     */
    public @Nullable PowerAuthApiAuthentication validateToken(@Nonnull String tokenHeader, @Nonnull List<PowerAuthCodeType> allowedAuthenticationCodeTypes) throws PowerAuthAuthenticationException {
        final PowerAuthApiAuthentication apiAuthentication = validateTokenWithActivationDetails(tokenHeader, allowedAuthenticationCodeTypes);
        if (!apiAuthentication.getAuthenticationContext().isValid()) {
            // Traditionally, failed token validation returns null value for PowerAuthApiAuthentication
            return null;
        }
        return apiAuthentication;
    }

    @Nonnull
    @Override
    public PowerAuthApiAuthentication validateTokenWithActivationDetails(@Nonnull String tokenHeader, @Nonnull List<PowerAuthCodeType> allowedAuthenticationCodeTypes) throws PowerAuthAuthenticationException {
        // Check for HTTP PowerAuth authorization header
        if (tokenHeader.equals("undefined")) {
            logger.warn("Token HTTP header is missing");
            throw new PowerAuthHeaderMissingException();
        }

        // Parse HTTP header
        final PowerAuthTokenHttpHeader header = new PowerAuthTokenHttpHeader().fromValue(tokenHeader);

        // Validate the header
        try {
            PowerAuthTokenHttpHeaderValidator.validate(header);
        } catch (InvalidPowerAuthHttpHeaderException ex) {
            logger.warn("Token validation failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthTokenInvalidException();
        }

        // Prepare authentication object
        final PowerAuthTokenAuthenticationImpl powerAuthTokenAuthentication = new PowerAuthTokenAuthenticationImpl();
        powerAuthTokenAuthentication.setTokenId(header.getTokenId());
        powerAuthTokenAuthentication.setTokenDigest(header.getTokenDigest());
        powerAuthTokenAuthentication.setNonce(header.getNonce());
        powerAuthTokenAuthentication.setTimestamp(header.getTimestamp());
        powerAuthTokenAuthentication.setVersion(header.getVersion());
        powerAuthTokenAuthentication.setHttpHeader(header);

        // Call the authentication based on token authentication object
        final PowerAuthApiAuthentication auth = (PowerAuthApiAuthentication) this.authenticate(powerAuthTokenAuthentication);

        // In case authentication is null, throw PowerAuth exception
        if (auth == null) {
            logger.debug("Invalid token value");
            throw new PowerAuthTokenInvalidException();
        }

        // Check if the authentication code type is allowed
        final PowerAuthCodeType expectedAuthenticationCodeType = auth.getAuthenticationContext().getAuthenticationCodeType();
        if (expectedAuthenticationCodeType == null || !allowedAuthenticationCodeTypes.contains(expectedAuthenticationCodeType)) {
            logger.warn("Invalid authentication code type in token validation: {}", expectedAuthenticationCodeType);
            throw new PowerAuthCodeTypeInvalidException();
        }

        return auth;
    }

}
