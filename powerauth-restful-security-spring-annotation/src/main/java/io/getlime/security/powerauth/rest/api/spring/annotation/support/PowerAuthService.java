/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2024 Wultra s.r.o.
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
package io.getlime.security.powerauth.rest.api.spring.annotation.support;

import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import io.getlime.security.powerauth.rest.api.spring.authentication.impl.PowerAuthApiAuthenticationImpl;
import io.getlime.security.powerauth.rest.api.spring.authentication.impl.PowerAuthSignatureAuthenticationImpl;
import io.getlime.security.powerauth.rest.api.spring.authentication.impl.PowerAuthTokenAuthenticationImpl;

/**
 * Interface for PowerAuth Service of various specific implementations. Allows abstracting API
 * to differentiate between the service published by PowerAuth Server and PowerAuth Cloud.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public interface PowerAuthService {

    /**
     * Method to validate authentication originating from the signature header and translating it to an
     * actual API authentication object.
     *
     * @param authentication Signature authentication.
     * @return API authentication.
     * @throws PowerAuthClientException In case validation of the signature fails.
     */
    PowerAuthApiAuthenticationImpl validateSignature(PowerAuthSignatureAuthenticationImpl authentication) throws PowerAuthClientException;

    /**
     * Method to validate authentication originating from the token header and translating it to an
     * actual API authentication object.
     *
     * @param authentication Token authentication.
     * @return API authentication.
     * @throws PowerAuthClientException In case validation of the signature fails.
     */
    PowerAuthApiAuthenticationImpl validateToken(PowerAuthTokenAuthenticationImpl authentication) throws PowerAuthClientException;

}
