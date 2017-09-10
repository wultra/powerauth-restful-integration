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

package io.getlime.security.powerauth.rest.api.jaxrs.converter;

import io.getlime.powerauth.soap.PowerAuthPortServiceStub;

/**
 * Helper class to convert from and to
 * {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.SignatureType} class.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class SignatureTypeConverter {

    /**
     * Convert {@link io.getlime.powerauth.soap.PowerAuthPortServiceStub.SignatureType}
     * from a {@link String} value.
     * @param signatureTypeString String value representing signature type.
     * @return Signature type.
     */
    public PowerAuthPortServiceStub.SignatureType convertFrom(String signatureTypeString) {

        // Default to strongest signature type on null value
        if (signatureTypeString == null) {
            return PowerAuthPortServiceStub.SignatureType.POSSESSION_KNOWLEDGE_BIOMETRY;
        }

        // Try to convert signature type
        try {
            signatureTypeString = signatureTypeString.toUpperCase();
            return PowerAuthPortServiceStub.SignatureType.Factory.fromValue(signatureTypeString);
        } catch (IllegalArgumentException e) {
            return PowerAuthPortServiceStub.SignatureType.POSSESSION_KNOWLEDGE_BIOMETRY;
        }

    }

}
