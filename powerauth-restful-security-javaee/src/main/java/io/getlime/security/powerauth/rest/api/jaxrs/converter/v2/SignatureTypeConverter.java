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
package io.getlime.security.powerauth.rest.api.jaxrs.converter.v2;

import io.getlime.powerauth.soap.v2.PowerAuthPortV2ServiceStub;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;

/**
 * Helper class to convert from and to
 * {@link io.getlime.powerauth.soap.v2.PowerAuthPortV2ServiceStub.SignatureType} class.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class SignatureTypeConverter {

    /**
     * Convert {@link io.getlime.powerauth.soap.v2.PowerAuthPortV2ServiceStub.SignatureType}
     * from a {@link String} value.
     * @param signatureTypeString String value representing signature type.
     * @return Signature type.
     */
    public PowerAuthPortV2ServiceStub.SignatureType convertFrom(String signatureTypeString) {

        // Return null value which represents an unknown signature type
        if (signatureTypeString == null) {
            return null;
        }

        // Try to convert signature type
        try {
            signatureTypeString = signatureTypeString.toUpperCase();
            return PowerAuthPortV2ServiceStub.SignatureType.Factory.fromValue(signatureTypeString);
        } catch (IllegalArgumentException e) {
            // Return null value which represents an unknown signature type
            return null;
        }

    }

    /**
     * Convert {@link io.getlime.powerauth.soap.v2.PowerAuthPortV2ServiceStub.SignatureType} from
     * {@link PowerAuthSignatureTypes}.
     * @param powerAuthSignatureTypes Signature type from crypto representation.
     * @return Signature type.
     */
    public PowerAuthPortV2ServiceStub.SignatureType convertFrom(PowerAuthSignatureTypes powerAuthSignatureTypes) {
        if (powerAuthSignatureTypes == null) {
            return null;
        }
        switch (powerAuthSignatureTypes) {
            case POSSESSION:
                return PowerAuthPortV2ServiceStub.SignatureType.POSSESSION;
            case KNOWLEDGE:
                return PowerAuthPortV2ServiceStub.SignatureType.KNOWLEDGE;
            case BIOMETRY:
                return PowerAuthPortV2ServiceStub.SignatureType.BIOMETRY;
            case POSSESSION_KNOWLEDGE:
                return PowerAuthPortV2ServiceStub.SignatureType.POSSESSION_KNOWLEDGE;
            case POSSESSION_BIOMETRY:
                return PowerAuthPortV2ServiceStub.SignatureType.POSSESSION_BIOMETRY;
            default:
                return PowerAuthPortV2ServiceStub.SignatureType.POSSESSION_KNOWLEDGE_BIOMETRY;
        }
    }

}
