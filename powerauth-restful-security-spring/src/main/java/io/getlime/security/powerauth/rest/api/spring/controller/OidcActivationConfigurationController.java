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
package io.getlime.security.powerauth.rest.api.spring.controller;

import io.getlime.security.powerauth.rest.api.model.request.OidcApplicationConfigurationRequest;
import io.getlime.security.powerauth.rest.api.model.response.OidcApplicationConfigurationResponse;
import io.getlime.security.powerauth.rest.api.spring.annotation.EncryptedRequestBody;
import io.getlime.security.powerauth.rest.api.spring.annotation.PowerAuthEncryption;
import io.getlime.security.powerauth.rest.api.spring.encryption.EncryptionContext;
import io.getlime.security.powerauth.rest.api.spring.encryption.EncryptionScope;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthApplicationConfigurationException;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthEncryptionException;
import io.getlime.security.powerauth.rest.api.spring.service.ApplicationConfigurationService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller that provides activation configuration.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@RestController
@RequestMapping("/pa/v3/config")
@Slf4j
@AllArgsConstructor
public class OidcActivationConfigurationController {

    private ApplicationConfigurationService applicationConfigurationService;

    /**
     * Fetch OIDC application configuration.
     *
     * @param request Request OIDC application configuration.
     * @param encryptionContext PowerAuth ECIES encryption context.
     * @return OIDC application configuration.
     * @throws PowerAuthApplicationConfigurationException In case there is an error while fetching claims.
     * @throws PowerAuthEncryptionException In case of failed encryption.
     */
    @PowerAuthEncryption(scope = EncryptionScope.APPLICATION_SCOPE)
    @PostMapping("oidc")
    public OidcApplicationConfigurationResponse fetchOidcConfiguration(@EncryptedRequestBody OidcApplicationConfigurationRequest request, EncryptionContext encryptionContext) throws PowerAuthApplicationConfigurationException, PowerAuthEncryptionException {
        if (encryptionContext == null) {
            logger.error("Encryption failed");
            throw new PowerAuthEncryptionException("Encryption failed");
        }

        return applicationConfigurationService.fetchOidcApplicationConfiguration(ApplicationConfigurationService.OidcQuery.builder()
                .providerId(request.getProviderId())
                .applicationId(encryptionContext.getApplicationKey())
                .build());
    }

}
