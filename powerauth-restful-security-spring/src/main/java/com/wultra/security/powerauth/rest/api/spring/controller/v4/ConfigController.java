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
package com.wultra.security.powerauth.rest.api.spring.controller.v4;

import com.wultra.security.powerauth.rest.api.model.response.v4.ConfigResponse;
import com.wultra.security.powerauth.rest.api.spring.annotation.PowerAuthEncryption;
import com.wultra.security.powerauth.rest.api.spring.encryption.EncryptionContext;
import com.wultra.security.powerauth.rest.api.spring.encryption.EncryptionScope;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthConfigException;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthEncryptionException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import com.wultra.security.powerauth.rest.api.spring.service.v4.ConfigService;
import com.wultra.security.powerauth.rest.api.spring.util.PowerAuthVersionUtil;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller delivering the secure configuration to mobile SDK callers over end-to-end encryption.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>4.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@RestController("configControllerV4")
@RequestMapping("/pa/v4/config")
@AllArgsConstructor
@Slf4j
public class ConfigController {

    private final ConfigService configServiceV4;

    /**
     * Fetch the configuration items visible in the application scope.
     *
     * @param encryptionContext PowerAuth encryption context.
     * @return Encrypted application-scope configuration items.
     * @throws PowerAuthConfigException In case fetching the configuration fails.
     * @throws PowerAuthEncryptionException In case of failed encryption.
     * @throws PowerAuthInvalidRequestException In case the PowerAuth protocol version is unsupported.
     */
    @PowerAuthEncryption(scope = EncryptionScope.APPLICATION_SCOPE)
    @PostMapping("application")
    public ConfigResponse fetchApplicationConfig(EncryptionContext encryptionContext) throws PowerAuthConfigException, PowerAuthEncryptionException, PowerAuthInvalidRequestException {
        logger.info("action: fetchApplicationConfig, state: initiated");
        if (encryptionContext == null) {
            logger.warn("Encryption failed");
            throw new PowerAuthEncryptionException("Encryption failed");
        }
        PowerAuthVersionUtil.checkUnsupportedVersionV4(encryptionContext.getVersion());

        final ConfigResponse response = configServiceV4.fetchApplicationConfig(encryptionContext);
        logger.info("action: fetchApplicationConfig, state: succeeded");
        return response;
    }

    /**
     * Fetch the configuration items visible in the activation scope (post-activation).
     *
     * @param encryptionContext PowerAuth encryption context.
     * @return Encrypted activation-scope configuration items.
     * @throws PowerAuthConfigException In case fetching the configuration fails.
     * @throws PowerAuthEncryptionException In case of failed encryption.
     * @throws PowerAuthInvalidRequestException In case the PowerAuth protocol version is unsupported.
     */
    @PowerAuthEncryption(scope = EncryptionScope.ACTIVATION_SCOPE)
    @PostMapping("activation")
    public ConfigResponse fetchActivationConfig(EncryptionContext encryptionContext) throws PowerAuthConfigException, PowerAuthEncryptionException, PowerAuthInvalidRequestException {
        logger.info("action: fetchActivationConfig, state: initiated, activationId: {}", encryptionContext != null ? encryptionContext.getActivationId() : null);
        if (encryptionContext == null) {
            logger.warn("Encryption failed");
            throw new PowerAuthEncryptionException("Encryption failed");
        }
        PowerAuthVersionUtil.checkUnsupportedVersionV4(encryptionContext.getVersion());

        final ConfigResponse response = configServiceV4.fetchActivationConfig(encryptionContext);
        logger.info("action: fetchActivationConfig, state: succeeded");
        return response;
    }

}

