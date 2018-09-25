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

package io.getlime.security.powerauth.rest.api.spring.converter.v2;

import io.getlime.powerauth.soap.v2.SignatureType;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;

/**
 * Helper class to convert from and to
 * {@link io.getlime.powerauth.soap.v2.SignatureType} class.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class SignatureTypeConverter {

    /**
     * Convert {@link io.getlime.powerauth.soap.v2.SignatureType}
     * from a {@link String} value.
     * @param signatureTypeString String value representing signature type.
     * @return Signature type.
     */
    public SignatureType convertFrom(String signatureTypeString) {

        // Default to strongest signature type on null value
        if (signatureTypeString == null) {
            return SignatureType.POSSESSION_KNOWLEDGE_BIOMETRY;
        }

        // Try to convert signature type
        try {
            signatureTypeString = signatureTypeString.toUpperCase();
            return SignatureType.fromValue(signatureTypeString);
        } catch (IllegalArgumentException e) {
            return SignatureType.POSSESSION_KNOWLEDGE_BIOMETRY;
        }

    }

    /**
     * Convert {@link SignatureType} from {@link PowerAuthSignatureTypes}.
     * @param powerAuthSignatureTypes Signature type from crypto representation.
     * @return Signature type.
     */
    public SignatureType convertFrom(PowerAuthSignatureTypes powerAuthSignatureTypes) {
        switch (powerAuthSignatureTypes) {
            case POSSESSION:
                return SignatureType.POSSESSION;
            case KNOWLEDGE:
                return SignatureType.KNOWLEDGE;
            case BIOMETRY:
                return SignatureType.BIOMETRY;
            case POSSESSION_KNOWLEDGE:
                return SignatureType.POSSESSION_KNOWLEDGE;
            case POSSESSION_BIOMETRY:
                return SignatureType.POSSESSION_BIOMETRY;
            default:
                return SignatureType.POSSESSION_KNOWLEDGE_BIOMETRY;
        }
    }

}
