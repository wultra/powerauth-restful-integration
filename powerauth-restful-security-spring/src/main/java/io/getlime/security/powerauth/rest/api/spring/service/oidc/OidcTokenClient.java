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

import com.wultra.core.rest.client.base.DefaultRestClient;
import com.wultra.core.rest.client.base.RestClient;
import com.wultra.core.rest.client.base.RestClientConfiguration;
import com.wultra.core.rest.client.base.RestClientException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * OIDC (OpenID Connect) client.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@Component
@AllArgsConstructor
@Slf4j
class OidcTokenClient {

    private OidcActivationConfigurationProperties configurationProperties;

    /**
     * Call token endpoint using {@code authorization_code} flow. Mind that <strong>the token is not verified yet</strong>.
     *
     * @param tokenRequest Token request.
     * @return Token response.
     * @throws RestClientException in case of error.
     */
    TokenResponse fetchTokenResponse(final TokenRequest tokenRequest) throws RestClientException {
        final HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        final org.springframework.security.oauth2.core.ClientAuthenticationMethod clientAuthenticationMethod = tokenRequest.getClientRegistration().getClientAuthenticationMethod();
        logger.debug("Using ClientAuthenticationMethod: {}", clientAuthenticationMethod);

        final ClientRegistration clientRegistration = tokenRequest.getClientRegistration();

        final MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type", "authorization_code");
        map.add("client_id", clientRegistration.getClientId());
        map.add("code", tokenRequest.getCode());
        map.add("redirect_uri", clientRegistration.getRedirectUri());

        final String codeVerifier = tokenRequest.getCodeVerifier();
        if (StringUtils.isNotBlank(codeVerifier)) {
            map.add("code_verifier", codeVerifier);
        }

        if (clientAuthenticationMethod == org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_POST) {
            map.add("client_secret", clientRegistration.getClientSecret());
        }

        final RestClient restClient = createRestClient(tokenRequest);

        final String tokenUrl = clientRegistration.getProviderDetails().getTokenUri();
        logger.debug("Calling token endpoint: {}", tokenUrl);
        final ResponseEntity<TokenResponse> response = restClient.post(tokenUrl, map, null, headers, new ParameterizedTypeReference<>(){});
        logger.debug("Token endpoint call finished: {}", tokenUrl);

        if (response == null) {
            throw new RestClientException("Response is null");
        }

        return response.getBody();
    }

    private RestClient createRestClient(final TokenRequest tokenRequest) throws RestClientException {
        final RestClientConfiguration restClientConfiguration = configurationProperties.getRestClientConfig();
        final org.springframework.security.oauth2.core.ClientAuthenticationMethod clientAuthenticationMethod = tokenRequest.getClientRegistration().getClientAuthenticationMethod();
        restClientConfiguration.setHttpBasicAuthEnabled(clientAuthenticationMethod == null || clientAuthenticationMethod == org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        restClientConfiguration.setHttpBasicAuthUsername(tokenRequest.getClientRegistration().getClientId());
        restClientConfiguration.setHttpBasicAuthPassword(tokenRequest.getClientRegistration().getClientSecret());

        return new DefaultRestClient(restClientConfiguration);
    }
}
