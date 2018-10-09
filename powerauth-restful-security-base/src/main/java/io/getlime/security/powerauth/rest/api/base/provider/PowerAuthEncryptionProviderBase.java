/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2017 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.powerauth.rest.api.base.provider;

import io.getlime.security.powerauth.http.PowerAuthEncryptionHttpHeader;
import io.getlime.security.powerauth.http.validator.InvalidPowerAuthHttpHeaderException;
import io.getlime.security.powerauth.http.validator.PowerAuthEncryptionHttpHeaderValidator;
import io.getlime.security.powerauth.rest.api.base.encryption.PowerAuthEciesDecryptorParameters;
import io.getlime.security.powerauth.rest.api.base.encryption.PowerAuthEciesEncryption;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthEncryptionException;

/**
 * Abstract class for PowerAuth encryption provider with common HTTP header parsing logic.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public abstract class PowerAuthEncryptionProviderBase {

    /**
     * Get ECIES decryptor parameters from PowerAuth server.
     *
     * @param activationId Activation ID (only used in activation scope, in application scope use null).
     * @param applicationKey Application key.
     * @param ephemeralPublicKey Ephemeral public key for ECIES.
     * @return ECIES decryptor parameters.
     * @throws PowerAuthEncryptionException In case PowerAuth server call fails.
     */
    public abstract PowerAuthEciesDecryptorParameters getEciesDecryptorParameters(String activationId, String applicationKey, String ephemeralPublicKey) throws PowerAuthEncryptionException;

    /**
     * Prepare ECIES data from PowerAuth encryption HTTP header.
     *
     * @param encryptionHttpHeader PowerAuth encryption HTTP header.
     * @return PowerAuth ECIES encryption object.
     * @throws PowerAuthEncryptionException In case PowerAuth encryption HTTP header is invalid.
     */
    public PowerAuthEciesEncryption prepareEciesEncryption(String encryptionHttpHeader) throws PowerAuthEncryptionException {
        // Check for HTTP PowerAuth encryption header
        if (encryptionHttpHeader == null || encryptionHttpHeader.equals("undefined")) {
            throw new PowerAuthEncryptionException("POWER_AUTH_ENCRYPTION_INVALID_EMPTY");
        }

        // Parse HTTP header
        PowerAuthEncryptionHttpHeader header = new PowerAuthEncryptionHttpHeader().fromValue(encryptionHttpHeader);

        // Validate the header
        try {
            PowerAuthEncryptionHttpHeaderValidator.validate(header);
        } catch (InvalidPowerAuthHttpHeaderException e) {
            throw new PowerAuthEncryptionException(e.getMessage());
        }

        // Prepare encryption object
        PowerAuthEciesEncryption eciesEncryption = new PowerAuthEciesEncryption();
        eciesEncryption.setApplicationKey(header.getApplicationKey());
        eciesEncryption.setActivationId(header.getActivationId());
        eciesEncryption.setVersion(header.getVersion());
        eciesEncryption.setHttpHeader(header);

        return eciesEncryption;
    }

}
