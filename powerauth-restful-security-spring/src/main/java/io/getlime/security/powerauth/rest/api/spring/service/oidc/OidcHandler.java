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
package io.getlime.security.powerauth.rest.api.spring.service.oidc;

import com.wultra.core.rest.client.base.RestClientException;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthActivationException;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthApplicationConfigurationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Wrap OIDC (OpenID Connect) client calls, add other logic such as validation.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@Component
@Slf4j
public class OidcHandler {

    private final Map<String, SignatureAlgorithm> signatureAlgorithms = new ConcurrentHashMap<>();

    private final OidcIdTokenDecoderFactory oidcIdTokenDecoderFactory;

    private final OidcTokenClient tokenClient;

    private final OidcApplicationConfigurationService applicationConfigurationService;

    @Autowired
    OidcHandler(final OidcTokenClient tokenClient, final OidcApplicationConfigurationService applicationConfigurationService) {
        this.tokenClient = tokenClient;
        this.applicationConfigurationService = applicationConfigurationService;
        oidcIdTokenDecoderFactory = new OidcIdTokenDecoderFactory();
        oidcIdTokenDecoderFactory.setJwsAlgorithmResolver(clientRegistration -> signatureAlgorithms.get(clientRegistration.getRegistrationId()));
    }

    /**
     * Retrieve user ID from a token, using {@code authorization_code} flow. The token is verified first.
     *
     * @param request Parameter object.
     * @return User ID.
     * @throws PowerAuthActivationException in case of error.
     */
    public String retrieveUserId(final OidcActivationContext request) throws PowerAuthActivationException {
        final OidcApplicationConfiguration oidcApplicationConfiguration = fetchOidcApplicationConfiguration(request);

        final ClientRegistration clientRegistration = createClientRegistration(request.getProviderId(), oidcApplicationConfiguration);

        signatureAlgorithms.putIfAbsent(clientRegistration.getRegistrationId(), mapSignatureAlgorithmFromConfiguration(oidcApplicationConfiguration));

        final TokenRequest tokenRequest = TokenRequest.builder()
                .code(request.getCode())
                .codeVerifier(request.getCodeVerifier())
                .clientRegistration(clientRegistration)
                .build();

        final TokenResponse tokenResponse = fetchToken(tokenRequest);
        final Jwt idToken = verifyAndDecode(tokenResponse, clientRegistration, request.getNonce());

        return idToken.getSubject();
    }

    private static ClientRegistration createClientRegistration(final String providerId, final OidcApplicationConfiguration oidcApplicationConfiguration) {
        logger.debug("Trying to configure via {}/.well-known/openid-configuration", oidcApplicationConfiguration.getIssuerUri());
        try {
            return ClientRegistrations.fromOidcIssuerLocation(oidcApplicationConfiguration.getIssuerUri())
                    .clientId(oidcApplicationConfiguration.getClientId())
                    .clientSecret(oidcApplicationConfiguration.getClientSecret())
                    .redirectUri(oidcApplicationConfiguration.getRedirectUri())
                    .build();
        } catch (Exception e) {
            logger.info("Unable to reach {}/.well-known/openid-configuration, fallback to manual config; {}", oidcApplicationConfiguration.getIssuerUri(), e.getMessage());
            logger.debug("Unable to reach {}/.well-known/openid-configuration", oidcApplicationConfiguration.getIssuerUri(), e);
            return ClientRegistration.withRegistrationId(providerId)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .clientId(oidcApplicationConfiguration.getClientId())
                    .clientSecret(oidcApplicationConfiguration.getClientSecret())
                    .clientAuthenticationMethod(convert(oidcApplicationConfiguration.getClientAuthenticationMethod()))
                    .tokenUri(oidcApplicationConfiguration.getTokenUri())
                    .jwkSetUri(oidcApplicationConfiguration.getJwkSetUri())
                    .authorizationUri(oidcApplicationConfiguration.getAuthorizeUri())
                    .redirectUri(oidcApplicationConfiguration.getRedirectUri())
                    .build();
        }
    }

    private static ClientAuthenticationMethod convert(final io.getlime.security.powerauth.rest.api.spring.service.oidc.ClientAuthenticationMethod source) {
        return switch(source) {
            case CLIENT_SECRET_POST -> ClientAuthenticationMethod.CLIENT_SECRET_POST;
            case CLIENT_SECRET_BASIC -> ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
        };
    }

    private OidcApplicationConfiguration fetchOidcApplicationConfiguration(final OidcActivationContext request) throws PowerAuthActivationException {
        try {
            return applicationConfigurationService.fetchOidcApplicationConfiguration(OidcConfigurationQuery.builder()
                    .applicationKey(request.getApplicationKey())
                    .providerId(request.getProviderId())
                    .build());
        } catch (PowerAuthApplicationConfigurationException e) {
            throw new PowerAuthActivationException(e);
        }
    }

    private TokenResponse fetchToken(final TokenRequest tokenRequest) throws PowerAuthActivationException {
        final String clientId = tokenRequest.getClientRegistration().getClientId();
        logger.debug("Fetching token, clientId: {}", clientId);
        try {
            final TokenResponse response = tokenClient.fetchTokenResponse(tokenRequest);
            logger.debug("Token fetched, verifying, clientId: {}", clientId);
            return response;
        } catch (RestClientException e) {
            throw new PowerAuthActivationException("Unable to get token response", e);
        }
    }

    private Jwt verifyAndDecode(final TokenResponse tokenResponse, final ClientRegistration clientRegistration, final String nonce) throws PowerAuthActivationException {
        final JwtDecoder jwtDecoder = oidcIdTokenDecoderFactory.createDecoder(clientRegistration);

        try {
            final Jwt idTokenJwt = jwtDecoder.decode(tokenResponse.getIdToken());
            validate(idTokenJwt, nonce, tokenResponse);
            return idTokenJwt;
        } catch (JwtException e) {
            throw new PowerAuthActivationException("Decoding JWT failed", e);
        }
    }

    private static void validate(final Jwt idTokenJwt, final String nonce, final TokenResponse tokenResponse) throws PowerAuthActivationException {
        if (!IdTokenValidator.isNonceValid(idTokenJwt, nonce)) {
            throw new PowerAuthActivationException("The nonce does not match");
        }
        if (!IdTokenValidator.isAtHashValid(idTokenJwt, tokenResponse.getAccessToken())) {
            throw new PowerAuthActivationException("The at_hash does not match");
        }
    }

    private static SignatureAlgorithm mapSignatureAlgorithmFromConfiguration(final OidcApplicationConfiguration oidcApplicationConfiguration) {
        final String signatureAlgorithmString = oidcApplicationConfiguration.getSignatureAlgorithm();
        final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.from(signatureAlgorithmString);
        return Objects.requireNonNullElse(signatureAlgorithm, SignatureAlgorithm.RS256);
    }

}
