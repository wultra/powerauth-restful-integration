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

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.request.GetEciesDecryptorRequest;
import com.wultra.security.powerauth.client.model.response.GetEciesDecryptorResponse;
import io.getlime.security.powerauth.rest.api.spring.encryption.PowerAuthEncryptorParameters;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthEncryptionException;
import io.getlime.security.powerauth.rest.api.spring.service.HttpCustomizationService;
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

    private final PowerAuthClient powerAuthClient;
    private final HttpCustomizationService httpCustomizationService;

    /**
     * Provide constructor.
     * @param powerAuthClient PowerAuth client.
     * @param httpCustomizationService HTTP customization service.
     */
    @Autowired
    public PowerAuthEncryptionProvider(PowerAuthClient powerAuthClient, HttpCustomizationService httpCustomizationService) {
        this.powerAuthClient = powerAuthClient;
        this.httpCustomizationService = httpCustomizationService;
    }

    @Override
    public @Nonnull PowerAuthEncryptorParameters getEciesDecryptorParameters(@Nullable String activationId, @Nonnull String applicationKey, @Nonnull String temporaryKeyId, @Nonnull String ephemeralPublicKey, @Nonnull String version, String nonce, Long timestamp) throws PowerAuthEncryptionException {
        try {
            final GetEciesDecryptorRequest eciesDecryptorRequest = new GetEciesDecryptorRequest();
            eciesDecryptorRequest.setActivationId(activationId);
            eciesDecryptorRequest.setApplicationKey(applicationKey);
            eciesDecryptorRequest.setTemporaryKeyId(temporaryKeyId);
            eciesDecryptorRequest.setEphemeralPublicKey(ephemeralPublicKey);
            eciesDecryptorRequest.setProtocolVersion(version);
            eciesDecryptorRequest.setNonce(nonce);
            eciesDecryptorRequest.setTimestamp(timestamp);
            final GetEciesDecryptorResponse eciesDecryptorResponse = powerAuthClient.getEciesDecryptor(
                    eciesDecryptorRequest,
                    httpCustomizationService.getQueryParams(),
                    httpCustomizationService.getHttpHeaders()
            );

            return new PowerAuthEncryptorParameters(eciesDecryptorResponse.getSecretKey(), eciesDecryptorResponse.getSharedInfo2());
        } catch (Exception ex) {
            logger.warn("Get ECIES decryptor call failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthEncryptionException();
        }
    }

}
