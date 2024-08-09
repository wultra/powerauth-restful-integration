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

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

/**
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@Slf4j
public class OAuth2TokenClient {

    private TokenResponse fetchTokenResponse(final TokenRequest tokenRequest) {
        final RestTemplate restTemplate = new RestTemplate();

        final HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        // Create a map of the key/value pairs that we want to supply in the body of the request
        final MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type", "authorization_code");
        map.add("client_id", tokenRequest.getClientId());
        map.add("client_secret", tokenRequest.getClientSecret());
        map.add("code", tokenRequest.getCode());
        map.add("redirect_uri", tokenRequest.getRedirectUri());

        final HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(map, headers);

        final ResponseEntity<TokenResponse> response =
                restTemplate.exchange(tokenRequest.getTokenUrl(),
                        HttpMethod.POST,
                        entity,
                        TokenResponse.class);

        return response.getBody();
    }

}
