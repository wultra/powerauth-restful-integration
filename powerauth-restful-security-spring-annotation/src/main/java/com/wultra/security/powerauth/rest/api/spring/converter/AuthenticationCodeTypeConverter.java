/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2025 Wultra s.r.o.
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
package com.wultra.security.powerauth.rest.api.spring.converter;

import com.wultra.security.powerauth.client.model.enumeration.v4.AuthenticationCodeType;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Helper class to convert from and to
 * {@link AuthenticationCodeType} class.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class AuthenticationCodeTypeConverter {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationCodeTypeConverter.class);

    /**
     * Convert {@link AuthenticationCodeType}
     * from a {@link String} value.
     * @param authenticationCodeTypeString String value representing authentication code type.
     * @return Authentication code type.
     */
    public AuthenticationCodeType convertFrom(String authenticationCodeTypeString) {

        if (authenticationCodeTypeString == null) {
            return null;
        }

        // Try to convert authentication code type
        try {
            authenticationCodeTypeString = authenticationCodeTypeString.toUpperCase();
            return AuthenticationCodeType.enumFromString(authenticationCodeTypeString);
        } catch (IllegalArgumentException ex) {
            logger.warn("Invalid authentication code type, error: {}", ex.getMessage());
            logger.debug("Error details", ex);
            // Return null value which represents an unknown authentication code type
            return null;
        }

    }

    /**
     * Convert {@link AuthenticationCodeType} from {@link PowerAuthCodeType}.
     * @param powerAuthCodeType Authentication code type from crypto representation.
     * @return Authentication code type.
     */
    public AuthenticationCodeType convertFrom(PowerAuthCodeType powerAuthCodeType) {
        return switch (powerAuthCodeType) {
            case POSSESSION -> AuthenticationCodeType.POSSESSION;
            case POSSESSION_KNOWLEDGE -> AuthenticationCodeType.POSSESSION_KNOWLEDGE;
            case POSSESSION_BIOMETRY -> AuthenticationCodeType.POSSESSION_BIOMETRY;
            default -> null;
        };
    }

}
