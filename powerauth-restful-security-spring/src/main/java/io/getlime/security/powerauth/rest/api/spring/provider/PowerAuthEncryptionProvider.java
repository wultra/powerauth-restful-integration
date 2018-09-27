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
package io.getlime.security.powerauth.rest.api.spring.provider;

import io.getlime.security.powerauth.http.PowerAuthEncryptionHttpHeader;
import io.getlime.security.powerauth.http.validator.InvalidPowerAuthHttpHeaderException;
import io.getlime.security.powerauth.http.validator.PowerAuthEncryptionHttpHeaderValidator;
import io.getlime.security.powerauth.rest.api.base.encryption.PowerAuthEciesEncryption;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthEncryptionException;
import io.getlime.security.powerauth.rest.api.base.provider.PowerAuthEncryptionProviderBase;
import io.getlime.security.powerauth.rest.api.spring.encryption.PowerAuthEciesEncryptionImpl;
import org.springframework.stereotype.Component;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Implementation of PowerAuth encryption provider.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@Component
public class PowerAuthEncryptionProvider extends PowerAuthEncryptionProviderBase  {

    @Override
    public PowerAuthEciesEncryption validateEciesEncryption(String encryptionHttpHeader) throws PowerAuthEncryptionException {
        // Check for HTTP PowerAuth Encryption signature header
        if (encryptionHttpHeader == null || encryptionHttpHeader.equals("undefined")) {
            throw new PowerAuthEncryptionException("POWER_AUTH_ENCRYPTION_INVALID_EMPTY");
        }

        // Parse HTTP header
        PowerAuthEncryptionHttpHeader header = new PowerAuthEncryptionHttpHeader().fromValue(encryptionHttpHeader);

        // Validate the header
        try {
            PowerAuthEncryptionHttpHeaderValidator.validate(header);
        } catch (InvalidPowerAuthHttpHeaderException e) {
            Logger.getLogger(this.getClass().getName()).log(Level.SEVERE, e.getMessage(), e);
            throw new PowerAuthEncryptionException(e.getMessage());
        }

        // Prepare encryption object
        PowerAuthEciesEncryptionImpl eciesEncryption = new PowerAuthEciesEncryptionImpl();
        eciesEncryption.setApplicationKey(header.getApplicationKey());
        eciesEncryption.setActivationId(header.getActivationId());
        eciesEncryption.setVersion(header.getVersion());

        return eciesEncryption;
    }
}
