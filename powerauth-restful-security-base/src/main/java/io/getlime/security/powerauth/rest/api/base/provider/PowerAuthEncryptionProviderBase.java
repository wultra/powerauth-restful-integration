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
package io.getlime.security.powerauth.rest.api.base.provider;

import io.getlime.security.powerauth.rest.api.base.encryption.PowerAuthEciesEncryption;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthEncryptionException;

/**
 * Abstract class for PowerAuth encryption provider.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public abstract class PowerAuthEncryptionProviderBase {

    /**
     * Validate the PowerAuth encryption HTTP header.
     *
     * @param encryptionHttpHeader PowerAuth encryption HTTP header as String.
     * @return Validated PowerAuth encryption HTTP header.
     * @throws PowerAuthEncryptionException In case PowerAuth encryption HTTP header is invalid.
     */
    public abstract PowerAuthEciesEncryption validateEciesEncryption(String encryptionHttpHeader) throws PowerAuthEncryptionException;

}
