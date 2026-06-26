/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2026 Wultra s.r.o.
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
package com.wultra.security.powerauth.rest.api.spring.service.v4;

import com.wultra.security.powerauth.client.model.entity.ConfigStoreItem;
import com.wultra.security.powerauth.client.model.enumeration.ConfigScope;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.LookupApplicationByAppKeyRequest;
import com.wultra.security.powerauth.client.model.request.v4.FetchConfigRequest;
import com.wultra.security.powerauth.client.model.response.LookupApplicationByAppKeyResponse;
import com.wultra.security.powerauth.client.model.response.v4.FetchConfigResponse;
import com.wultra.security.powerauth.client.v4.PowerAuthClient;
import com.wultra.security.powerauth.rest.api.model.entity.ConfigItem;
import com.wultra.security.powerauth.rest.api.model.response.v4.ConfigResponse;
import com.wultra.security.powerauth.rest.api.spring.encryption.EncryptionContext;
import com.wultra.security.powerauth.rest.api.spring.encryption.EncryptionScope;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthConfigException;
import com.wultra.security.powerauth.rest.api.spring.service.HttpCustomizationService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Test for {@link ConfigService}.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@ExtendWith(MockitoExtension.class)
class ConfigServiceTest {

    private static final String APPLICATION_KEY = "AIsOlIghnLztV2np3SANnQ==";
    private static final String APPLICATION_ID = "application-1";
    private static final String ACTIVATION_ID = "e43a5dec-afea-4f17-a92a-3b5c8a4e1b3e";

    @Mock
    private PowerAuthClient powerAuthClient;

    @Mock
    private HttpCustomizationService httpCustomizationService;

    @InjectMocks
    private ConfigService tested;

    @Test
    void fetchApplicationConfig_resolvesApplicationIdAndMapsItems() throws Exception {
        stubLookup();
        final FetchConfigResponse fetchResponse = new FetchConfigResponse();
        fetchResponse.setApplicationId(APPLICATION_ID);
        fetchResponse.getConfigs().add(item("base_url", "https://example.com", ConfigScope.APPLICATION));
        when(powerAuthClient.fetchConfig(any(FetchConfigRequest.class), any(), any())).thenReturn(fetchResponse);

        final ConfigResponse response = tested.fetchApplicationConfig(context(EncryptionScope.APPLICATION_SCOPE, null));

        final ArgumentCaptor<FetchConfigRequest> captor = ArgumentCaptor.forClass(FetchConfigRequest.class);
        verify(powerAuthClient).fetchConfig(captor.capture(), any(), any());
        assertEquals(APPLICATION_ID, captor.getValue().getApplicationId());
        assertNull(captor.getValue().getActivationId());

        assertEquals(1, response.config().size());
        final ConfigItem item = response.config().get(0);
        assertEquals("base_url", item.key());
        assertEquals("https://example.com", item.value());
        assertEquals(com.wultra.security.powerauth.rest.api.model.entity.ConfigScope.APPLICATION, item.scope());
    }

    @Test
    void fetchActivationConfig_passesActivationIdAndMapsScopes() throws Exception {
        stubLookup();
        final FetchConfigResponse fetchResponse = new FetchConfigResponse();
        fetchResponse.setApplicationId(APPLICATION_ID);
        fetchResponse.setActivationId(ACTIVATION_ID);
        fetchResponse.getConfigs().add(item("base_url", "https://example.com", ConfigScope.APPLICATION));
        fetchResponse.getConfigs().add(item("token", "secret", ConfigScope.ACTIVATION));
        when(powerAuthClient.fetchConfig(any(FetchConfigRequest.class), any(), any())).thenReturn(fetchResponse);

        final ConfigResponse response = tested.fetchActivationConfig(context(EncryptionScope.ACTIVATION_SCOPE, ACTIVATION_ID));

        final ArgumentCaptor<FetchConfigRequest> captor = ArgumentCaptor.forClass(FetchConfigRequest.class);
        verify(powerAuthClient).fetchConfig(captor.capture(), any(), any());
        assertEquals(APPLICATION_ID, captor.getValue().getApplicationId());
        assertEquals(ACTIVATION_ID, captor.getValue().getActivationId());

        assertEquals(List.of(
                        com.wultra.security.powerauth.rest.api.model.entity.ConfigScope.APPLICATION,
                        com.wultra.security.powerauth.rest.api.model.entity.ConfigScope.ACTIVATION),
                response.config().stream().map(ConfigItem::scope).toList());
    }

    @Test
    void fetchApplicationConfig_emptyConfigReturnsEmptyList() throws Exception {
        stubLookup();
        when(powerAuthClient.fetchConfig(any(FetchConfigRequest.class), any(), any())).thenReturn(new FetchConfigResponse());

        final ConfigResponse response = tested.fetchApplicationConfig(context(EncryptionScope.APPLICATION_SCOPE, null));

        assertNotNull(response.config());
        assertTrue(response.config().isEmpty());
    }

    @Test
    void fetchApplicationConfig_wrapsClientException() throws Exception {
        when(powerAuthClient.lookupApplicationByAppKey(any(LookupApplicationByAppKeyRequest.class), any(), any()))
                .thenThrow(new PowerAuthClientException("client error"));

        assertThrows(PowerAuthConfigException.class,
                () -> tested.fetchApplicationConfig(context(EncryptionScope.APPLICATION_SCOPE, null)));
    }

    private void stubLookup() throws PowerAuthClientException {
        final LookupApplicationByAppKeyResponse lookupResponse = new LookupApplicationByAppKeyResponse();
        lookupResponse.setApplicationId(APPLICATION_ID);
        when(powerAuthClient.lookupApplicationByAppKey(any(LookupApplicationByAppKeyRequest.class), any(), any()))
                .thenReturn(lookupResponse);
    }

    private static ConfigStoreItem item(String key, Object value, ConfigScope scope) {
        final ConfigStoreItem item = new ConfigStoreItem();
        item.setKey(key);
        item.setValue(value);
        item.setScope(scope);
        return item;
    }

    private static EncryptionContext context(EncryptionScope scope, String activationId) {
        return new EncryptionContext(APPLICATION_KEY, activationId, "4.0", null, scope);
    }

}

