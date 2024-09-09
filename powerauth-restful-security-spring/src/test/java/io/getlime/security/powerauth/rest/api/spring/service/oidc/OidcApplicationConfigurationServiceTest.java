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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.request.GetApplicationConfigRequest;
import com.wultra.security.powerauth.client.model.request.LookupApplicationByAppKeyRequest;
import com.wultra.security.powerauth.client.model.response.GetApplicationConfigResponse;
import com.wultra.security.powerauth.client.model.response.LookupApplicationByAppKeyResponse;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthApplicationConfigurationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

/**
 * Test for {@link OidcApplicationConfigurationService}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@ExtendWith(MockitoExtension.class)
class OidcApplicationConfigurationServiceTest {

    @Mock
    private PowerAuthClient powerAuthClient;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @InjectMocks
    private OidcApplicationConfigurationService tested;

    @Test
    void testFetchOidcApplicationConfiguration() throws Exception {
        final LookupApplicationByAppKeyRequest lookupRequest = new LookupApplicationByAppKeyRequest();
        lookupRequest.setApplicationKey("AIsOlIghnLztV2np3SANnQ==");

        final LookupApplicationByAppKeyResponse lookupResponse = new LookupApplicationByAppKeyResponse();
        lookupResponse.setApplicationId("application-1");

        when(powerAuthClient.lookupApplicationByAppKey(lookupRequest))
                .thenReturn(lookupResponse);

        final GetApplicationConfigRequest configRequest = new GetApplicationConfigRequest();
        configRequest.setApplicationId("application-1");

        final GetApplicationConfigResponse configResponse = createResponse();
        when(powerAuthClient.getApplicationConfig(configRequest))
                .thenReturn(configResponse);

        final OidcApplicationConfiguration result = tested.fetchOidcApplicationConfiguration(OidcConfigurationQuery.builder()
                .applicationKey("AIsOlIghnLztV2np3SANnQ==")
                .providerId("xyz999")
                .build());

        assertEquals("xyz999", result.getProviderId());
        assertEquals("jabberwocky", result.getClientId());
        assertEquals("https://redirect.example.com", result.getRedirectUri());
        assertEquals("https://issuer.example.com", result.getIssuerUri());
        assertEquals("openid", result.getScopes());
        assertEquals("https://token.example.com", result.getTokenUri());
        assertEquals("https://authorize.example.com", result.getAuthorizeUri());
        assertEquals("ES256", result.getSignatureAlgorithm());
    }

    @Test
    void testFetchOidcApplicationConfiguration_invalidProviderId() throws Exception {
        final LookupApplicationByAppKeyRequest lookupRequest = new LookupApplicationByAppKeyRequest();
        lookupRequest.setApplicationKey("AIsOlIghnLztV2np3SANnQ==");

        final LookupApplicationByAppKeyResponse lookupResponse = new LookupApplicationByAppKeyResponse();
        lookupResponse.setApplicationId("application-1");

        when(powerAuthClient.lookupApplicationByAppKey(lookupRequest))
                .thenReturn(lookupResponse);

        final GetApplicationConfigRequest configRequest = new GetApplicationConfigRequest();
        configRequest.setApplicationId("application-1");

        final GetApplicationConfigResponse configResponse = createResponse();
        when(powerAuthClient.getApplicationConfig(configRequest))
                .thenReturn(configResponse);

        final Exception e = assertThrows(PowerAuthApplicationConfigurationException.class, () -> tested.fetchOidcApplicationConfiguration(OidcConfigurationQuery.builder()
                .applicationKey("AIsOlIghnLztV2np3SANnQ==")
                .providerId("non-existing")
                .build()));

        assertEquals("Fetching application configuration failed, application ID: application-1, provider ID: non-existing", e.getMessage());
    }

    private GetApplicationConfigResponse createResponse() throws JsonProcessingException {
        final String json = """
                {
                   "applicationId": "application-1",
                   "applicationConfigs": [
                     {
                       "key": "oauth2_providers",
                       "values": [
                         {
                           "providerId": "abc123",
                           "clientId": "1234567890abcdef",
                           "clientSecret": "top secret",
                           "scopes": "openid",
                           "authorizeUri": "https://...",
                           "redirectUri": "https://...",
                           "tokenUri": "https://...",
                           "issuerUri": "https://...",
                           "userInfoUri": "https://..."
                         },
                         {
                           "providerId": "xyz999",
                           "clientId": "jabberwocky",
                           "clientSecret": "top secret",
                           "scopes": "openid",
                           "authorizeUri": "https://authorize.example.com",
                           "redirectUri": "https://redirect.example.com",
                           "issuerUri": "https://issuer.example.com",
                           "tokenUri": "https://token.example.com",
                           "userInfoUri": "https://...",
                           "signatureAlgorithm": "ES256"
                         }
                       ]
                     }
                   ]
                 }
                """;

        return objectMapper.readValue(json, GetApplicationConfigResponse.class);
    }
}