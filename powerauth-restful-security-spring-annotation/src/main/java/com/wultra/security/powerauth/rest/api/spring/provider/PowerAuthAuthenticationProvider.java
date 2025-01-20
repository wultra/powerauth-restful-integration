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

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.ValidateTokenRequest;
import com.wultra.security.powerauth.client.model.request.VerifySignatureRequest;
import com.wultra.security.powerauth.client.model.response.ValidateTokenResponse;
import com.wultra.security.powerauth.client.model.response.VerifySignatureResponse;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import com.wultra.security.powerauth.http.PowerAuthHttpBody;
import com.wultra.security.powerauth.http.PowerAuthHttpHeader;
import com.wultra.security.powerauth.http.PowerAuthSignatureHttpHeader;
import com.wultra.security.powerauth.http.PowerAuthTokenHttpHeader;
import com.wultra.security.powerauth.http.validator.InvalidPowerAuthHttpHeaderException;
import com.wultra.security.powerauth.http.validator.PowerAuthSignatureHttpHeaderValidator;
import com.wultra.security.powerauth.http.validator.PowerAuthTokenHttpHeaderValidator;
import com.wultra.security.powerauth.rest.api.spring.authentication.PowerAuthActivation;
import com.wultra.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import com.wultra.security.powerauth.rest.api.spring.authentication.impl.PowerAuthActivationImpl;
import com.wultra.security.powerauth.rest.api.spring.authentication.impl.PowerAuthApiAuthenticationImpl;
import com.wultra.security.powerauth.rest.api.spring.authentication.impl.PowerAuthSignatureAuthenticationImpl;
import com.wultra.security.powerauth.rest.api.spring.authentication.impl.PowerAuthTokenAuthenticationImpl;
import com.wultra.security.powerauth.rest.api.spring.converter.ActivationStatusConverter;
import com.wultra.security.powerauth.rest.api.spring.converter.SignatureTypeConverter;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthHeaderMissingException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthSignatureInvalidException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthSignatureTypeInvalidException;
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

    private final PowerAuthClient powerAuthClient;
    private final ActivationStatusConverter activationStatusConverter;
    private final HttpCustomizationService httpCustomizationService;

    /**
     * Provider constructor.
     * @param powerAuthClient PowerAuth client.
     * @param activationStatusConverter Activation status converter.
     * @param httpCustomizationService HTTP customization service.
     */
    @Autowired
    public PowerAuthAuthenticationProvider(PowerAuthClient powerAuthClient, ActivationStatusConverter activationStatusConverter, HttpCustomizationService httpCustomizationService) {
        this.powerAuthClient = powerAuthClient;
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
        // Handle signature based authentications
        if (authentication instanceof PowerAuthSignatureAuthenticationImpl) {
            return validateSignatureAuthentication((PowerAuthSignatureAuthenticationImpl) authentication);
        }
        // Handle basic token-based authentications
        else if (authentication instanceof PowerAuthTokenAuthenticationImpl) {
            return validateTokenAuthentication((PowerAuthTokenAuthenticationImpl) authentication);
        }
        // Return null in case unknown authentication type is provided
        return null;
    }

    /**
     * Validate signature based authentication.
     *
     * @param authentication Signature based authentication object.
     * @return API authentication object in case of successful authentication, null otherwise.
     */
    private PowerAuthApiAuthenticationImpl validateSignatureAuthentication(PowerAuthSignatureAuthenticationImpl authentication) {

        if (authentication.getSignatureType() != null) {

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
                verifyRequest.setForcedSignatureVersion(authentication.getForcedSignatureVersion());
            }

            final VerifySignatureResponse response;
            try {
                response = powerAuthClient.verifySignature(
                        verifyRequest,
                        httpCustomizationService.getQueryParams(),
                        httpCustomizationService.getHttpHeaders()
                );
            } catch (PowerAuthClientException ex) {
                logger.warn("Signature validation failed, error: {}", ex.getMessage());
                logger.debug("Error details", ex);
                return null;
            }
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
        } else {
            return null;
        }
    }

    /**
     * Validate basic token-based authentication.
     *
     * @param authentication Token based authentication object.
     * @return API authentication object in case of successful authentication, null otherwise.
     */
    private PowerAuthApiAuthenticationImpl validateTokenAuthentication(PowerAuthTokenAuthenticationImpl authentication) {
        try {
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

    /**
     * Validate the signature from the PowerAuth HTTP header against the provided HTTP method, request body and URI identifier.
     * Make sure to accept only allowed signatures.
     * @param httpMethod HTTP method (GET, POST, ...)
     * @param httpBody Body of the HTTP request.
     * @param requestUriIdentifier Request URI identifier.
     * @param httpAuthorizationHeader PowerAuth HTTP authorization header.
     * @param allowedSignatureTypes Allowed types of the signature.
     * @param forcedSignatureVersion Forced signature version, optional parameter used during upgrade.
     * @return Instance of a PowerAuthApiAuthenticationImpl on successful authorization.
     * @throws PowerAuthAuthenticationException In case authorization fails, exception is raised.
     */
    public PowerAuthApiAuthentication validateRequestSignature(
            @Nonnull String httpMethod,
            @Nullable byte[] httpBody,
            @Nonnull String requestUriIdentifier,
            @Nonnull String httpAuthorizationHeader,
            @Nonnull List<PowerAuthSignatureTypes> allowedSignatureTypes,
            @Nullable Integer forcedSignatureVersion
    ) throws PowerAuthAuthenticationException {
        final PowerAuthApiAuthentication apiAuthentication = validateRequestSignatureWithActivationDetails(httpMethod, httpBody, requestUriIdentifier, httpAuthorizationHeader, allowedSignatureTypes, forcedSignatureVersion);
        if (!apiAuthentication.getAuthenticationContext().isValid()) {
            // Traditionally, failed signature validation returns null value for PowerAuthApiAuthentication
            return null;
        }
       return apiAuthentication;
    }

    @Override
    public @Nonnull PowerAuthApiAuthentication validateRequestSignatureWithActivationDetails(@Nonnull String httpMethod, @Nullable byte[] httpBody, @Nonnull String requestUriIdentifier, @Nonnull String httpAuthorizationHeader, @Nonnull List<PowerAuthSignatureTypes> allowedSignatureTypes, @Nullable Integer forcedSignatureVersion) throws PowerAuthAuthenticationException {
        // Check for HTTP PowerAuth signature header
        if (httpAuthorizationHeader.equals("undefined")) {
            logger.warn("Signature HTTP header is missing");
            throw new PowerAuthHeaderMissingException();
        }

        // Parse HTTP header
        final PowerAuthSignatureHttpHeader header = new PowerAuthSignatureHttpHeader().fromValue(httpAuthorizationHeader);

        // Validate the header
        try {
            PowerAuthSignatureHttpHeaderValidator.validate(header);
        } catch (InvalidPowerAuthHttpHeaderException ex) {
            logger.warn("Signature HTTP header validation failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthSignatureInvalidException();
        }

        // Check if the signature type is allowed
        final PowerAuthSignatureTypes expectedSignatureType = PowerAuthSignatureTypes.getEnumFromString(header.getSignatureType());
        if (expectedSignatureType == null || !allowedSignatureTypes.contains(expectedSignatureType)) {
            logger.warn("Invalid signature type: {}", expectedSignatureType);
            throw new PowerAuthSignatureTypeInvalidException();
        }

        // Configure PowerAuth authentication object
        final PowerAuthSignatureAuthenticationImpl powerAuthAuthentication = new PowerAuthSignatureAuthenticationImpl();
        powerAuthAuthentication.setActivationId(header.getActivationId());
        powerAuthAuthentication.setApplicationKey(header.getApplicationKey());
        powerAuthAuthentication.setNonce(Base64.getDecoder().decode(header.getNonce()));
        powerAuthAuthentication.setSignatureType(header.getSignatureType());
        powerAuthAuthentication.setSignature(header.getSignature());
        powerAuthAuthentication.setHttpMethod(httpMethod);
        powerAuthAuthentication.setRequestUri(requestUriIdentifier);
        powerAuthAuthentication.setData(httpBody);
        powerAuthAuthentication.setVersion(header.getVersion());
        powerAuthAuthentication.setHttpHeader(header);
        powerAuthAuthentication.setForcedSignatureVersion(forcedSignatureVersion);

        // Call the authentication based on signature authentication object
        final PowerAuthApiAuthentication auth = (PowerAuthApiAuthentication) this.authenticate(powerAuthAuthentication);

        // In case authentication is null, throw PowerAuth exception
        if (auth == null) {
            logger.debug("Signature validation failed");
            throw new PowerAuthSignatureInvalidException();
        }

        return auth;
    }

    /**
     * Validate token header for simple token-based authentication.
     *
     * @param tokenHeader Token header.
     * @param allowedSignatureTypes Allowed types of the signature.
     * @return Authentication object in case authentication is correctly obtained.
     * @throws PowerAuthAuthenticationException In case of authentication failure.
     */
    public @Nullable PowerAuthApiAuthentication validateToken(@Nonnull String tokenHeader, @Nonnull List<PowerAuthSignatureTypes> allowedSignatureTypes) throws PowerAuthAuthenticationException {
        final PowerAuthApiAuthentication apiAuthentication = validateTokenWithActivationDetails(tokenHeader, allowedSignatureTypes);
        if (!apiAuthentication.getAuthenticationContext().isValid()) {
            // Traditionally, failed token validation returns null value for PowerAuthApiAuthentication
            return null;
        }
        return apiAuthentication;
    }

    @Nonnull
    @Override
    public PowerAuthApiAuthentication validateTokenWithActivationDetails(@Nonnull String tokenHeader, @Nonnull List<PowerAuthSignatureTypes> allowedSignatureTypes) throws PowerAuthAuthenticationException {
        // Check for HTTP PowerAuth signature header
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

        // Check if the signature type is allowed
        final PowerAuthSignatureTypes expectedSignatureType = auth.getAuthenticationContext().getSignatureType();
        if (expectedSignatureType == null || !allowedSignatureTypes.contains(expectedSignatureType)) {
            logger.warn("Invalid signature type in token validation: {}", expectedSignatureType);
            throw new PowerAuthSignatureTypeInvalidException();
        }

        return auth;
    }

}
