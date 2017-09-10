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

package io.getlime.security.powerauth.rest.api.base.validator;

import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.http.PowerAuthHttpHeader;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;

/**
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class PowerAuthHttpHeaderValidator {

    public static void validate(PowerAuthHttpHeader header) throws PowerAuthAuthenticationException {

        // Check if the parsing was successful
        if (header == null) {
            throw new PowerAuthAuthenticationException("POWER_AUTH_SIGNATURE_INVALID_EMPTY");
        }

        // Check activation ID
        String activationId = header.getActivationId();
        if (activationId == null) {
            throw new PowerAuthAuthenticationException("POWER_AUTH_ACTIVATION_ID_EMPTY");
        }

        // Check nonce
        String nonce = header.getNonce();
        if (nonce == null) {
            throw new PowerAuthAuthenticationException("POWER_AUTH_NONCE_EMPTY");
        }

        // Check signature type
        String signatureType = header.getSignatureType();
        if (signatureType == null) {
            throw new PowerAuthAuthenticationException("POWER_AUTH_SIGNATURE_TYPE_EMPTY");
        }

        // Check signature
        String signature = header.getSignature();
        if (signature == null) {
            throw new PowerAuthAuthenticationException("POWER_AUTH_SIGNATURE_EMPTY");
        }

        // Check application key.
        String applicationKey = header.getApplicationKey();
        if (applicationKey == null) {
            throw new PowerAuthAuthenticationException("POWER_AUTH_APPLICATION_EMPTY");
        }

    }

}
