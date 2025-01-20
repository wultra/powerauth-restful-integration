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
package com.wultra.security.powerauth.rest.api.spring.service.oidc;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.entity.ApplicationConfigurationItem;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.GetApplicationConfigRequest;
import com.wultra.security.powerauth.client.model.request.LookupApplicationByAppKeyRequest;
import com.wultra.security.powerauth.client.model.response.GetApplicationConfigResponse;
import com.wultra.security.powerauth.client.model.response.LookupApplicationByAppKeyResponse;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthApplicationConfigurationException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Objects;

/**
 * Application configuration service for OIDC.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@Component
@AllArgsConstructor
@Slf4j
public class OidcApplicationConfigurationService {

    private static final String OAUTH2_PROVIDERS = "oauth2_providers";

    private final PowerAuthClient powerAuthClient;

    private final ObjectMapper objectMapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    /**
     * Provide OIDC application configuration.
     *
     * @param request Query object.
     * @return OIDC application configuration
     * @throws PowerAuthApplicationConfigurationException in case of error.
     */
    public OidcApplicationConfiguration fetchOidcApplicationConfiguration(final OidcConfigurationQuery request) throws PowerAuthApplicationConfigurationException {
        try {
            final String applicationId = fetchApplicationIdByApplicationKey(request.applicationKey());

            final GetApplicationConfigRequest configRequest = new GetApplicationConfigRequest();
            configRequest.setApplicationId(applicationId);

            final GetApplicationConfigResponse applicationConfig = powerAuthClient.getApplicationConfig(configRequest);
            return applicationConfig.getApplicationConfigs().stream()
                    .filter(it -> it.getKey().equals(OAUTH2_PROVIDERS))
                    .findFirst()
                    .map(ApplicationConfigurationItem::getValues)
                    .map(it -> convert(it, request.providerId()))
                    .orElseThrow(() ->
                            new PowerAuthApplicationConfigurationException("Fetching application configuration failed, application ID: %s, provider ID: %s".formatted(applicationId, request.providerId())));
        } catch (PowerAuthClientException e) {
            throw new PowerAuthApplicationConfigurationException("Fetching application configuration failed.", e);
        }
    }

    private OidcApplicationConfiguration convert(List<Object> values, String providerId) {
        return values.stream()
                .map(this::convert)
                .filter(Objects::nonNull)
                .filter(it -> it.getProviderId().equals(providerId))
                .findFirst()
                .orElse(null);
    }

    private OidcApplicationConfiguration convert(Object value) {
        try {
            return objectMapper.convertValue(value, OidcApplicationConfiguration.class);
        } catch (IllegalArgumentException e) {
            logger.warn("Unable to convert {}", value, e);
            return null;
        }
    }

    private String fetchApplicationIdByApplicationKey(final String applicationKey) throws PowerAuthClientException {
        final LookupApplicationByAppKeyRequest request = new LookupApplicationByAppKeyRequest();
        request.setApplicationKey(applicationKey);

        final LookupApplicationByAppKeyResponse applicationResponse = powerAuthClient.lookupApplicationByAppKey(request);
        return applicationResponse.getApplicationId();
    }

}
