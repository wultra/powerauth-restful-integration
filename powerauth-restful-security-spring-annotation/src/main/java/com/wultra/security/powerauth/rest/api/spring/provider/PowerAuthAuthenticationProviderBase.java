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

import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import com.wultra.security.powerauth.rest.api.spring.encryption.PowerAuthEncryptorData;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthRequestFilterException;
import com.wultra.security.powerauth.rest.api.spring.model.ActivationStatus;
import com.wultra.security.powerauth.rest.api.spring.model.PowerAuthRequestBody;
import com.wultra.security.powerauth.rest.api.spring.model.PowerAuthRequestObjects;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Abstract class for PowerAuth authentication provider.
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
public abstract class PowerAuthAuthenticationProviderBase {

    private static final Logger logger = LoggerFactory.getLogger(PowerAuthAuthenticationProviderBase.class);

    /**
     * Validate the authentication from the PowerAuth HTTP header against the provided HTTP method, request body and URI identifier.
     * Make sure to accept only allowed authentication types. Return an instance of PowerAuthApiAuthentication on successful authorization,
     * null value is returned on failed authorization. A check of null return value is used to determine the authorization result.
     * @param httpMethod HTTP method (GET, POST, ...)
     * @param httpBody Body of the HTTP request.
     * @param requestUriIdentifier Request URI identifier.
     * @param httpAuthorizationHeader PowerAuth HTTP authorization header.
     * @param allowedAuthenticationCodeTypes Allowed authentication code types.
     * @param allowedStates Allowed states for authentication.
     * @param forcedAuthenticationVersion Forced authentication version during upgrade.
     * @return Instance of a PowerAuthApiAuthentication on successful authorization, null value on failed authorization.
     * @throws PowerAuthAuthenticationException In case authorization fails, exception is raised.
     */
    public abstract @Nullable PowerAuthApiAuthentication validateRequestAuthentication(@Nonnull String httpMethod, @Nullable byte[] httpBody, @Nonnull String requestUriIdentifier, @Nonnull String httpAuthorizationHeader, @Nonnull List<PowerAuthCodeType> allowedAuthenticationCodeTypes, @Nonnull List<ActivationStatus> allowedStates, @Nullable Integer forcedAuthenticationVersion) throws PowerAuthAuthenticationException;

    /**
     * Validate the authentication from the PowerAuth HTTP header against the provided HTTP method, request body and URI identifier.
     * Make sure to accept only allowed authentication code types. Return an instance of PowerAuthApiAuthentication on both successful and
     * failed authorization. A check of null return value cannot be used to determine the authorization result, the actual
     * result is available in the authorization context.
     * @param httpMethod HTTP method (GET, POST, ...)
     * @param httpBody Body of the HTTP request.
     * @param requestUriIdentifier Request URI identifier.
     * @param httpAuthorizationHeader PowerAuth HTTP authorization header.
     * @param allowedAuthenticationCodeTypes Allowed authentication code types.
     * @param allowedStates Allowed states for authentication.
     * @param forcedAuthenticationVersion Forced authentication version during upgrade.
     * @return Instance of a PowerAuthApiAuthentication on successful authorization.
     * @throws PowerAuthAuthenticationException In case authorization fails, exception is raised.
     */
    public abstract @Nonnull PowerAuthApiAuthentication validateRequestAuthenticationWithActivationDetails(@Nonnull String httpMethod, @Nullable byte[] httpBody, @Nonnull String requestUriIdentifier, @Nonnull String httpAuthorizationHeader, @Nonnull List<PowerAuthCodeType> allowedAuthenticationCodeTypes, @Nonnull List<ActivationStatus> allowedStates, @Nullable Integer forcedAuthenticationVersion) throws PowerAuthAuthenticationException;

    /**
     * Validate the token digest from PowerAuth authentication header.
     * @param httpAuthorizationHeader HTTP header with token digest.
     * @param allowedAuthenticationCodeTypes Allowed authentication code types.
     * @return Instance of a PowerAuthApiAuthentication on successful authorization.
     * @throws PowerAuthAuthenticationException In case authorization fails, exception is raised.
     */
    public abstract @Nullable PowerAuthApiAuthentication validateToken(@Nonnull String httpAuthorizationHeader, @Nonnull List<PowerAuthCodeType> allowedAuthenticationCodeTypes) throws PowerAuthAuthenticationException;

    /**
     * Validate the token digest from PowerAuth authentication header.
     * @param httpAuthorizationHeader HTTP header with token digest.
     * @param allowedAuthenticationCodeTypes Allowed authentication code types.
     * @return Instance of a PowerAuthApiAuthentication on successful authorization.
     * @throws PowerAuthAuthenticationException In case authorization fails, exception is raised.
     */
    public abstract @Nonnull PowerAuthApiAuthentication validateTokenWithActivationDetails(@Nonnull String httpAuthorizationHeader, @Nonnull List<PowerAuthCodeType> allowedAuthenticationCodeTypes) throws PowerAuthAuthenticationException;

    /**
     * The same as {{@link #validateRequestAuthentication(String, byte[], String, String, List, List, Integer)} but uses default accepted authentication code type (2FA or 3FA) and does not specify forced authentication version.
     * @param httpMethod HTTP method (GET, POST, ...)
     * @param httpBody Request body
     * @param requestUriIdentifier Request URI identifier.
     * @param httpAuthorizationHeader PowerAuth HTTP authorization header.
     * @return Instance of a PowerAuthApiAuthentication on successful authorization.
     * @throws PowerAuthAuthenticationException In case authorization fails, exception is raised.
     */
    public @Nullable PowerAuthApiAuthentication validateRequestAuthentication(@Nonnull String httpMethod, @Nullable byte[] httpBody, @Nonnull String requestUriIdentifier, @Nonnull String httpAuthorizationHeader) throws PowerAuthAuthenticationException {
        final List<PowerAuthCodeType> defaultAllowedAuthenticationCodeTypes = new ArrayList<>();
        defaultAllowedAuthenticationCodeTypes.add(PowerAuthCodeType.POSSESSION_KNOWLEDGE);
        defaultAllowedAuthenticationCodeTypes.add(PowerAuthCodeType.POSSESSION_BIOMETRY);
        defaultAllowedAuthenticationCodeTypes.add(PowerAuthCodeType.POSSESSION_KNOWLEDGE_BIOMETRY);
        final List<ActivationStatus> defaultAllowedStates = Collections.singletonList(ActivationStatus.ACTIVE);
        return this.validateRequestAuthentication(httpMethod, httpBody, requestUriIdentifier, httpAuthorizationHeader, defaultAllowedAuthenticationCodeTypes, defaultAllowedStates, null);
    }

    /**
     * Validate a request authentication, make sure only supported authentication code types are used, do not use forced authentication version during upgrade.
     * @param servletRequest HTTPServletRequest with signed data.
     * @param requestUriIdentifier Request URI identifier.
     * @param httpAuthorizationHeader PowerAuth HTTP authorization header.
     * @param allowedAuthenticationCodeTypes Allowed authentication code types.
     * @param allowedStates Allowed states for authentication.
     * @return Instance of a PowerAuthApiAuthentication on successful authorization.
     * @throws PowerAuthAuthenticationException In case authorization fails, exception is raised.
     */
    public @Nullable PowerAuthApiAuthentication validateRequestAuthentication(@Nonnull HttpServletRequest servletRequest, @Nonnull String requestUriIdentifier, @Nonnull String httpAuthorizationHeader, @Nonnull List<PowerAuthCodeType> allowedAuthenticationCodeTypes, @Nonnull List<ActivationStatus> allowedStates) throws PowerAuthAuthenticationException {
        // Get HTTP method and body bytes
        String requestMethod = servletRequest.getMethod().toUpperCase();
        byte[] requestBodyBytes = extractRequestBodyBytes(servletRequest);
        return this.validateRequestAuthentication(requestMethod, requestBodyBytes, requestUriIdentifier, httpAuthorizationHeader, allowedAuthenticationCodeTypes, allowedStates, null);
    }

    /**
     * Validate a request authentication, make sure only supported authentication code types are used, do not use forced authentication version during upgrade.
     * @param servletRequest HTTPServletRequest with signed data.
     * @param requestUriIdentifier Request URI identifier.
     * @param httpAuthorizationHeader PowerAuth HTTP authorization header.
     * @param allowedAuthenticationCodeTypes Allowed authentication code types.
     * @param allowedStates Allowed states for authentication.
     * @return Instance of a PowerAuthApiAuthentication on successful authorization.
     * @throws PowerAuthAuthenticationException In case authorization fails, exception is raised.
     */
    public @Nonnull PowerAuthApiAuthentication validateRequestAuthenticationWithActivationDetails(@Nonnull HttpServletRequest servletRequest, @Nonnull String requestUriIdentifier, @Nonnull String httpAuthorizationHeader, @Nonnull List<PowerAuthCodeType> allowedAuthenticationCodeTypes, @Nonnull List<ActivationStatus> allowedStates) throws PowerAuthAuthenticationException {
        // Get HTTP method and body bytes
        String requestMethod = servletRequest.getMethod().toUpperCase();
        byte[] requestBodyBytes = extractRequestBodyBytes(servletRequest);
        return this.validateRequestAuthenticationWithActivationDetails(requestMethod, requestBodyBytes, requestUriIdentifier, httpAuthorizationHeader, allowedAuthenticationCodeTypes, allowedStates, null);
    }

    /**
     * Validate a request authentication, make sure only supported authentication code types are used and allow specification of forced authentication version.
     * @param servletRequest HTTPServletRequest with signed data.
     * @param requestUriIdentifier Request URI identifier.
     * @param httpAuthorizationHeader PowerAuth HTTP authorization header.
     * @param allowedAuthenticationCodeTypes Allowed authentication code types.
     * @param allowedStates Allowed states for authentication.
     * @param forcedAuthenticationVersion Forced authentication version during upgrade.
     * @return Instance of a PowerAuthApiAuthentication on successful authorization.
     * @throws PowerAuthAuthenticationException In case authorization fails, exception is raised.
     */
    public @Nullable PowerAuthApiAuthentication validateRequestAuthentication(@Nonnull HttpServletRequest servletRequest, @Nonnull String requestUriIdentifier, @Nonnull String httpAuthorizationHeader, @Nonnull List<PowerAuthCodeType> allowedAuthenticationCodeTypes, @Nonnull List<ActivationStatus> allowedStates, @Nullable Integer forcedAuthenticationVersion) throws PowerAuthAuthenticationException {
        // Get HTTP method and body bytes
        String requestMethod = servletRequest.getMethod().toUpperCase();
        byte[] requestBodyBytes = extractRequestBodyBytes(servletRequest);
        return this.validateRequestAuthentication(requestMethod, requestBodyBytes, requestUriIdentifier, httpAuthorizationHeader, allowedAuthenticationCodeTypes, allowedStates, forcedAuthenticationVersion);
    }

    /**
     * The same as {@link #validateRequestAuthentication(HttpServletRequest, String, String, List, List, Integer)} but uses default accepted authentication code type (2FA or 3FA) and does not specify forced authentication version.
     * @param servletRequest HTTPServletRequest with signed data.
     * @param requestUriIdentifier Request URI identifier.
     * @param httpAuthorizationHeader PowerAuth HTTP authorization header.
     * @return Instance of a PowerAuthApiAuthentication on successful authorization.
     * @throws PowerAuthAuthenticationException In case authorization fails, exception is raised.
     */
    public @Nullable PowerAuthApiAuthentication validateRequestAuthentication(@Nonnull HttpServletRequest servletRequest, @Nonnull String requestUriIdentifier, @Nonnull String httpAuthorizationHeader) throws PowerAuthAuthenticationException {
        List<PowerAuthCodeType> defaultAllowedAuthenticationCodeTypes = new ArrayList<>();
        defaultAllowedAuthenticationCodeTypes.add(PowerAuthCodeType.POSSESSION_KNOWLEDGE);
        defaultAllowedAuthenticationCodeTypes.add(PowerAuthCodeType.POSSESSION_BIOMETRY);
        defaultAllowedAuthenticationCodeTypes.add(PowerAuthCodeType.POSSESSION_KNOWLEDGE_BIOMETRY);
        final List<ActivationStatus> defaultAllowedStates = Collections.singletonList(ActivationStatus.ACTIVE);
        return this.validateRequestAuthentication(servletRequest, requestUriIdentifier, httpAuthorizationHeader, defaultAllowedAuthenticationCodeTypes, defaultAllowedStates);
    }

    /**
     * Validate the token digest from PowerAuth authentication header.
     * @param tokenHeader HTTP header with token digest.
     * @return Instance of a PowerAuthApiAuthentication on successful authorization.
     * @throws PowerAuthAuthenticationException In case authorization fails, exception is raised.
     */
    public @Nullable PowerAuthApiAuthentication validateToken(@Nonnull String tokenHeader) throws PowerAuthAuthenticationException {
        List<PowerAuthCodeType> defaultAllowedAuthenticationCodeTypes = new ArrayList<>();
        defaultAllowedAuthenticationCodeTypes.add(PowerAuthCodeType.POSSESSION_KNOWLEDGE);
        defaultAllowedAuthenticationCodeTypes.add(PowerAuthCodeType.POSSESSION_BIOMETRY);
        defaultAllowedAuthenticationCodeTypes.add(PowerAuthCodeType.POSSESSION_KNOWLEDGE_BIOMETRY);
        return this.validateToken(tokenHeader, defaultAllowedAuthenticationCodeTypes);
    }

    /**
     * Extract request body bytes from HTTP servlet request. In case the data was transparently decrypted, use the decrypted request data.
     * @param servletRequest HTTP servlet request.
     * @return Request body bytes.
     * @throws PowerAuthAuthenticationException In case request body is invalid.
     */
    public @Nullable byte[] extractRequestBodyBytes(@Nonnull HttpServletRequest servletRequest) throws PowerAuthAuthenticationException {
        if (servletRequest.getAttribute(PowerAuthRequestObjects.ENCRYPTION_OBJECT) != null) {
            // Implementation of sign-then-encrypt - in case the encryption object is present and authentication is valid, use decrypted request data
            PowerAuthEncryptorData encryption = (PowerAuthEncryptorData) servletRequest.getAttribute(PowerAuthRequestObjects.ENCRYPTION_OBJECT);
            return encryption.getDecryptedRequest();
        } else {
            // Request data was not encrypted - use regular PowerAuth request body for authentication code validation
            PowerAuthRequestBody requestBody = ((PowerAuthRequestBody) servletRequest.getAttribute(PowerAuthRequestObjects.REQUEST_BODY));
            if (requestBody == null) {
                logger.warn("The X-PowerAuth-Request-Body request attribute is missing. Register the PowerAuthRequestFilter to fix this error.");
                throw new PowerAuthRequestFilterException();
            }
            return requestBody.getRequestBytes();
        }
    }
}
