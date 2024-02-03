/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2018 Wultra s.r.o.
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
package io.getlime.security.powerauth.rest.api.spring.provider;

import com.wultra.security.powerauth.client.model.request.GetEciesDecryptorRequest;
import io.getlime.security.powerauth.rest.api.spring.encryption.EncryptionRequest;
import io.getlime.security.powerauth.rest.api.spring.encryption.PowerAuthEncryptorParameters;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthEncryptionException;
import io.getlime.security.powerauth.rest.api.spring.service.HttpCustomizationService;
import io.getlime.security.powerauth.rest.api.spring.service.PowerAuthService;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Implementation of PowerAuth encryption provider.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@Component
public class PowerAuthEncryptionProvider extends PowerAuthEncryptionProviderBase  {

    private static final Logger logger = LoggerFactory.getLogger(PowerAuthEncryptionProvider.class);

    private final PowerAuthService powerAuthService;

    /**
     * Provide constructor.
     * @param powerAuthService PowerAuth service.
     * @param httpCustomizationService HTTP customization service.
     */
    @Autowired
    public PowerAuthEncryptionProvider(PowerAuthService powerAuthService, HttpCustomizationService httpCustomizationService) {
        this.powerAuthService = powerAuthService;
    }

    @Override
    public @Nonnull PowerAuthEncryptorParameters getEciesDecryptorParameters(@Nullable String activationId, @Nonnull String applicationKey, @Nonnull String ephemeralPublicKey, @Nonnull String version, String nonce, Long timestamp) throws PowerAuthEncryptionException {
        try {
            final EncryptionRequest encryptionRequest = EncryptionRequest.builder()
                    .activationId(activationId)
                    .applicationKey(applicationKey)
                    .ephemeralPublicKey(ephemeralPublicKey)
                    .nonce(nonce)
                    .protocolVersion(version)
                    .timestamp(timestamp)
                    .build();
            return powerAuthService.prepareEncryptionContext(encryptionRequest);
        } catch (Exception ex) {
            logger.warn("Get ECIES decryptor call failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthEncryptionException();
        }
    }

}
