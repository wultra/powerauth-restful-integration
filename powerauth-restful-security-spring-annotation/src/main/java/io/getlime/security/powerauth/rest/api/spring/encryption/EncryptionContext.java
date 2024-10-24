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

package io.getlime.security.powerauth.rest.api.spring.encryption;

import io.getlime.security.powerauth.http.PowerAuthHttpHeader;
import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Class for storing PowerAuth End-To-End encryption context derived from HTTP headers.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Getter
@AllArgsConstructor
public class EncryptionContext {
    /**
     * Application key.
     */
    private final String applicationKey;
    /**
     * Activation ID.
     */
    private final String activationId;
    /**
     * Protocol version.
     */
    private final String version;

    /**
     * PowerAuth HTTP header used for deriving ECIES encryption context.
     */
    private final PowerAuthHttpHeader httpHeader;
    /**
     * Scope of the encryption.
     */
    private final EncryptionScope encryptionScope;
}