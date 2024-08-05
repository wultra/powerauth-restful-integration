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
package io.getlime.security.powerauth.rest.api.spring.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.request.GetApplicationConfigRequest;
import com.wultra.security.powerauth.client.model.response.GetApplicationConfigResponse;
import io.getlime.security.powerauth.rest.api.model.response.OidcApplicationConfigurationResponse;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthApplicationConfigurationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

/**
 * Test for {@link ApplicationConfigurationService}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@ExtendWith(MockitoExtension.class)
class ApplicationConfigurationServiceTest {

    @Mock
    private PowerAuthClient powerAuthClient;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @InjectMocks
    private ApplicationConfigurationService tested;

    @Test
    void testFetchOidcApplicationConfiguration() throws Exception {
        final GetApplicationConfigRequest request = new GetApplicationConfigRequest();
        request.setApplicationId("application-1");

        final GetApplicationConfigResponse response = createResponse();
        when(powerAuthClient.getApplicationConfig(request))
                .thenReturn(response);

        final OidcApplicationConfigurationResponse result = tested.fetchOidcApplicationConfiguration(ApplicationConfigurationService.OidcQuery.builder()
                .applicationId("application-1")
                .providerId("xyz999")
                .build());

        assertEquals("xyz999", result.getProviderId());
        assertEquals("jabberwocky", result.getClientId());
        assertEquals(List.of("openid"), result.getScopes());
        assertEquals("https://redirect.example.com", result.getRedirectUri());
        assertEquals("https://authorize.example.com", result.getAuthorizeUri());
    }

    @Test
    void testFetchOidcApplicationConfiguration_invalidProviderId() throws Exception {
        final GetApplicationConfigRequest request = new GetApplicationConfigRequest();
        request.setApplicationId("application-1");

        final GetApplicationConfigResponse response = createResponse();
        when(powerAuthClient.getApplicationConfig(request))
                .thenReturn(response);

        final Exception e = assertThrows(PowerAuthApplicationConfigurationException.class, () -> tested.fetchOidcApplicationConfiguration(ApplicationConfigurationService.OidcQuery.builder()
                .applicationId("application-1")
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
                           "scopes": [
                             "openid"
                           ],
                           "authorizeUri": "https://...",
                           "redirectUri": "https://...",
                           "tokenUri": "https://...",
                           "userInfoUri": "https://..."
                         },
                         {
                           "providerId": "xyz999",
                           "clientId": "jabberwocky",
                           "clientSecret": "top secret",
                           "scopes": [
                             "openid"
                           ],
                           "authorizeUri": "https://authorize.example.com",
                           "redirectUri": "https://redirect.example.com",
                           "tokenUri": "https://...",
                           "userInfoUri": "https://..."
                         }
                       ]
                     }
                   ]
                 }
                """;

        return objectMapper.readValue(json, GetApplicationConfigResponse.class);
    }
}
