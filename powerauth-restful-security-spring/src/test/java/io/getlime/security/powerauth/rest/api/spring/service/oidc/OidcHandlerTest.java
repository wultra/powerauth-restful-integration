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
package io.getlime.security.powerauth.rest.api.spring.service.oidc;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Test for {@link OidcHandler}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@ExtendWith(MockitoExtension.class)
class OidcHandlerTest {

    @Mock
    private OidcTokenClient tokenClient;

    @Mock
    private OidcApplicationConfigurationService applicationConfigurationService;

    @Mock
    private OidcIdTokenDecoderFactory oidcIdTokenDecoderFactory;

    @Mock
    private JwtDecoder jwtDecoder;

    @InjectMocks
    private OidcHandler tested;

    @Test
    void issueToken() throws Exception {
        final String applicationKey = "AIsOlIghnLztV2np3SANnQ==";
        final String providerId = "xyz999";

        final OidcActivationContext context = OidcActivationContext.builder()
                .applicationKey(applicationKey)
                .providerId(providerId)
                .code("auth_code_123")
                .codeVerifier("code_verifier_123")
                .nonce("nonce_123")
                .build();

        final OidcApplicationConfiguration configuration = new OidcApplicationConfiguration();
        configuration.setProviderId(providerId);
        configuration.setClientId("client_123");
        configuration.setClientSecret("secret_123");
        configuration.setRedirectUri("https://redirect.example.com");
        configuration.setTokenUri("https://token.example.com");
        configuration.setAuthorizeUri("https://authorize.example.com");
        configuration.setIssuerUri("https://issuer.example.com");
        configuration.setJwkSetUri("https://jwks.example.com");
        configuration.setSignatureAlgorithm("RS256");
        configuration.setTokenClaimNames(List.of("jti", "n/a"));
        configuration.setPkceEnabled(false);
        configuration.setClientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);

        final OidcConfigurationQuery expectedQuery = OidcConfigurationQuery.builder()
                .applicationKey(applicationKey)
                .providerId(providerId)
                .build();

        when(applicationConfigurationService.fetchOidcApplicationConfiguration(expectedQuery))
                .thenReturn(configuration);

        final TokenResponse tokenResponse = new TokenResponse();
        tokenResponse.setIdToken("id_token_123");
        tokenResponse.setAccessToken("access_token_123");

        when(tokenClient.fetchTokenResponse(any(TokenRequest.class)))
                .thenReturn(tokenResponse);

        ReflectionTestUtils.setField(tested, "oidcIdTokenDecoderFactory", oidcIdTokenDecoderFactory);
        when(oidcIdTokenDecoderFactory.createDecoder(any()))
                .thenReturn(jwtDecoder);

        final Map<String, Object> headers = Map.of("alg", "RS256");

        final Map<String, Object> claims = Map.of(
                "sub", "user123",
                "nonce", "nonce_123",
                "jti", "value1",
                "sid", "value2");

        final Jwt jwt = new Jwt(
                "id_token_123",
                Instant.now(),
                Instant.now().plusSeconds(3600),
                headers,
                claims
        );

        when(jwtDecoder.decode("id_token_123"))
                .thenReturn(jwt);

        final TokenData result = tested.issueToken(context);

        assertNotNull(result);
        assertEquals("user123", result.getUserId());
        assertEquals(1, result.getClaims().size());
        assertEquals("value1", result.getClaims().get("jti"));
    }
}
