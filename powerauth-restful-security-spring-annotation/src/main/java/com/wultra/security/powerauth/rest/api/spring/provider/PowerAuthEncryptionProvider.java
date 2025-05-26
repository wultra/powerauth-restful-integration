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
package com.wultra.security.powerauth.rest.api.spring.provider;

import com.wultra.security.powerauth.client.model.request.v3.GetEciesDecryptorRequest;
import com.wultra.security.powerauth.client.model.request.v4.ExtractEncryptorRequest;
import com.wultra.security.powerauth.client.model.response.v3.GetEciesDecryptorResponse;
import com.wultra.security.powerauth.client.model.response.v4.ExtractEncryptorResponse;
import com.wultra.security.powerauth.rest.api.spring.converter.ActivationStatusConverter;
import com.wultra.security.powerauth.rest.api.spring.encryption.PowerAuthEncryptorParameters;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthEncryptionException;
import com.wultra.security.powerauth.rest.api.spring.model.ActivationStatus;
import com.wultra.security.powerauth.rest.api.spring.service.HttpCustomizationService;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.AllArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Stream;

/**
 * Implementation of PowerAuth encryption provider.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@Component
@AllArgsConstructor
public class PowerAuthEncryptionProvider extends PowerAuthEncryptionProviderBase  {

    private static final Logger logger = LoggerFactory.getLogger(PowerAuthEncryptionProvider.class);

    private final com.wultra.security.powerauth.client.v3.PowerAuthClient powerAuthClientV3;
    private final com.wultra.security.powerauth.client.v4.PowerAuthClient powerAuthClientV4;
    private final HttpCustomizationService httpCustomizationService;
    private final ActivationStatusConverter activationStatusConverter;

    @Override
    public @Nonnull PowerAuthEncryptorParameters getEciesEncryptorParameters(@Nullable String activationId, @Nonnull String applicationKey, @Nonnull String temporaryKeyId, @Nonnull String ephemeralPublicKey, @Nonnull String version, String nonce, Long timestamp) throws PowerAuthEncryptionException {
        try {
            final GetEciesDecryptorRequest eciesDecryptorRequest = new GetEciesDecryptorRequest();
            eciesDecryptorRequest.setActivationId(activationId);
            eciesDecryptorRequest.setApplicationKey(applicationKey);
            eciesDecryptorRequest.setTemporaryKeyId(temporaryKeyId);
            eciesDecryptorRequest.setEphemeralPublicKey(ephemeralPublicKey);
            eciesDecryptorRequest.setProtocolVersion(version);
            eciesDecryptorRequest.setNonce(nonce);
            eciesDecryptorRequest.setTimestamp(timestamp);
            final GetEciesDecryptorResponse eciesDecryptorResponse = powerAuthClientV3.getEciesDecryptor(
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

    @Override
    public @Nonnull PowerAuthEncryptorParameters getAeadEncryptorParameters(String activationId, @Nonnull String applicationKey, @Nonnull String temporaryKeyId, @Nonnull String version, @Nonnull String nonce, @Nonnull Long timestamp, @Nonnull ActivationStatus[] allowedStates) throws PowerAuthEncryptionException {
        try {
            final List<com.wultra.security.powerauth.client.model.enumeration.ActivationStatus> convertedStates = Stream.of(allowedStates)
                    .map(activationStatusConverter::convert)
                    .toList();
            final ExtractEncryptorRequest encryptorRequest = new ExtractEncryptorRequest();
            encryptorRequest.setActivationId(activationId);
            encryptorRequest.setApplicationKey(applicationKey);
            encryptorRequest.setTemporaryKeyId(temporaryKeyId);
            encryptorRequest.setProtocolVersion(version);
            encryptorRequest.setNonce(nonce);
            encryptorRequest.setTimestamp(timestamp);
            encryptorRequest.setAllowedStates(convertedStates);
            final ExtractEncryptorResponse encryptorResponse = powerAuthClientV4.extractEncryptor(
                    encryptorRequest,
                    httpCustomizationService.getQueryParams(),
                    httpCustomizationService.getHttpHeaders()
            );

            return new PowerAuthEncryptorParameters(encryptorResponse.getSecretKey(), encryptorResponse.getSharedInfo2());
        } catch (Exception ex) {
            logger.warn("Extract encryptor call failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthEncryptionException();
        }
    }
}
