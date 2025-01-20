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
package com.wultra.security.powerauth.rest.api.spring.util;

import com.wultra.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthSignatureInvalidException;
import lombok.extern.slf4j.Slf4j;

/**
 * Utility class for common handling of the authentication object.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Slf4j
public final class PowerAuthAuthenticationUtil {

    /**
     * Prevent instantiation of utility class.
     */
    private PowerAuthAuthenticationUtil() {
        throw new IllegalStateException("Utility class");
    }


    /**
     * Check if the authentication represents a valid user.
     *
     * @param auth Authentication object
     * @throws PowerAuthSignatureInvalidException Exception in case the authentication do not represent the user.
     */
    public static void checkAuthentication(PowerAuthApiAuthentication auth) throws PowerAuthSignatureInvalidException {
        if (auth == null
                || auth.getActivationContext() == null
                || auth.getActivationContext().getActivationId() == null) {
            logger.debug("Signature validation failed");
            throw new PowerAuthSignatureInvalidException();
        }
    }

}
