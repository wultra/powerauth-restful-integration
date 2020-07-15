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
package io.getlime.security.powerauth.rest.api.jaxrs.converter.v3;

import com.wultra.security.powerauth.client.v3.PowerAuthPortV3ServiceStub;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Helper class to convert from and to
 * {@link PowerAuthPortV3ServiceStub.SignatureType} class.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class SignatureTypeConverter {

    private static final Logger logger = LoggerFactory.getLogger(SignatureTypeConverter.class);

    /**
     * Convert {@link PowerAuthPortV3ServiceStub.SignatureType}
     * from a {@link String} value.
     * @param signatureTypeString String value representing signature type.
     * @return Signature type.
     */
    public PowerAuthPortV3ServiceStub.SignatureType convertFrom(String signatureTypeString) {

        // Return null value which represents an unknown signature type
        if (signatureTypeString == null) {
            return null;
        }

        // Try to convert signature type
        try {
            signatureTypeString = signatureTypeString.toUpperCase();
            return PowerAuthPortV3ServiceStub.SignatureType.Factory.fromValue(signatureTypeString);
        } catch (IllegalArgumentException ex) {
            logger.warn("Invalid signature type, error: {}", ex.getMessage());
            // Return null value which represents an unknown signature type
            return null;
        }

    }

    /**
     * Convert {@link PowerAuthPortV3ServiceStub.SignatureType} from
     * {@link PowerAuthSignatureTypes}.
     * @param powerAuthSignatureTypes Signature type from crypto representation.
     * @return Signature type.
     */
    public PowerAuthPortV3ServiceStub.SignatureType convertFrom(PowerAuthSignatureTypes powerAuthSignatureTypes) {
        if (powerAuthSignatureTypes == null) {
            return null;
        }
        switch (powerAuthSignatureTypes) {
            case POSSESSION:
                return PowerAuthPortV3ServiceStub.SignatureType.POSSESSION;
            case KNOWLEDGE:
                return PowerAuthPortV3ServiceStub.SignatureType.KNOWLEDGE;
            case BIOMETRY:
                return PowerAuthPortV3ServiceStub.SignatureType.BIOMETRY;
            case POSSESSION_KNOWLEDGE:
                return PowerAuthPortV3ServiceStub.SignatureType.POSSESSION_KNOWLEDGE;
            case POSSESSION_BIOMETRY:
                return PowerAuthPortV3ServiceStub.SignatureType.POSSESSION_BIOMETRY;
            default:
                return null;
        }
    }

}
