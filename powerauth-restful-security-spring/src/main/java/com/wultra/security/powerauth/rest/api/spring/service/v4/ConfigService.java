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
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.request.LookupApplicationByAppKeyRequest;
import com.wultra.security.powerauth.client.model.request.v4.FetchConfigRequest;
import com.wultra.security.powerauth.client.model.response.LookupApplicationByAppKeyResponse;
import com.wultra.security.powerauth.client.model.response.v4.FetchConfigResponse;
import com.wultra.security.powerauth.client.v4.PowerAuthClient;
import com.wultra.security.powerauth.rest.api.model.entity.ConfigItem;
import com.wultra.security.powerauth.rest.api.model.entity.ConfigScope;
import com.wultra.security.powerauth.rest.api.model.response.v4.ConfigResponse;
import com.wultra.security.powerauth.rest.api.spring.encryption.EncryptionContext;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthConfigException;
import com.wultra.security.powerauth.rest.api.spring.service.HttpCustomizationService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Service implementing the secure configuration delivery to mobile SDK callers.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>4.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service("configServiceV4")
@AllArgsConstructor
@Slf4j
public class ConfigService {

    private final PowerAuthClient powerAuthClient;
    private final HttpCustomizationService httpCustomizationService;

    /**
     * Fetch the configuration items visible in the application scope.
     *
     * @param encryptionContext PowerAuth encryption context derived from the validated E2EE request.
     * @return Application-scope configuration items.
     * @throws PowerAuthConfigException In case the internal API call fails.
     */
    public ConfigResponse fetchApplicationConfig(EncryptionContext encryptionContext) throws PowerAuthConfigException {
        try {
            final String applicationId = resolveApplicationId(encryptionContext.getApplicationKey());

            final FetchConfigRequest fetchRequest = new FetchConfigRequest();
            fetchRequest.setApplicationId(applicationId);

            final FetchConfigResponse fetchResponse = powerAuthClient.fetchConfig(
                    fetchRequest,
                    httpCustomizationService.getQueryParams(),
                    httpCustomizationService.getHttpHeaders()
            );
            return convert(fetchResponse);
        } catch (PowerAuthClientException ex) {
            logger.warn("PowerAuth application configuration fetch failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthConfigException();
        }
    }

    /**
     * Fetch the configuration items visible in the activation scope.
     *
     * @param encryptionContext PowerAuth encryption context derived from the validated E2EE request.
     * @return Activation-scope configuration items (application-level sections plus the activation's per-device items).
     * @throws PowerAuthConfigException In case the internal API call fails.
     */
    public ConfigResponse fetchActivationConfig(EncryptionContext encryptionContext) throws PowerAuthConfigException {
        try {
            final String applicationId = resolveApplicationId(encryptionContext.getApplicationKey());
            final String activationId = encryptionContext.getActivationId();

            final FetchConfigRequest fetchRequest = new FetchConfigRequest();
            fetchRequest.setApplicationId(applicationId);
            fetchRequest.setActivationId(activationId);

            final FetchConfigResponse fetchResponse = powerAuthClient.fetchConfig(
                    fetchRequest,
                    httpCustomizationService.getQueryParams(),
                    httpCustomizationService.getHttpHeaders()
            );
            return convert(fetchResponse);
        } catch (PowerAuthClientException ex) {
            logger.warn("PowerAuth activation configuration fetch failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthConfigException();
        }
    }

    private String resolveApplicationId(String applicationKey) throws PowerAuthClientException {
        final LookupApplicationByAppKeyRequest lookupRequest = new LookupApplicationByAppKeyRequest();
        lookupRequest.setApplicationKey(applicationKey);
        final LookupApplicationByAppKeyResponse lookupResponse = powerAuthClient.lookupApplicationByAppKey(
                lookupRequest,
                httpCustomizationService.getQueryParams(),
                httpCustomizationService.getHttpHeaders()
        );
        return lookupResponse.getApplicationId();
    }

    private static ConfigResponse convert(FetchConfigResponse fetchResponse) {
        final ConfigResponse response = new ConfigResponse();
        if (fetchResponse.getConfigs() != null) {
            for (ConfigStoreItem storeItem : fetchResponse.getConfigs()) {
                final ConfigItem item = new ConfigItem();
                item.setKey(storeItem.getKey());
                item.setValue(storeItem.getValue());
                item.setScope(convertScope(storeItem.getScope()));
                response.getConfig().add(item);
            }
        }
        return response;
    }

    private static ConfigScope convertScope(com.wultra.security.powerauth.client.model.enumeration.ConfigScope scope) {
        if (scope == null) {
            return null;
        }
        return switch (scope) {
            case APPLICATION -> ConfigScope.APPLICATION;
            case ACTIVATION -> ConfigScope.ACTIVATION;
        };
    }

}
