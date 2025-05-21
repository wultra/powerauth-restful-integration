/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2021 Wultra s.r.o.
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
package io.getlime.security.powerauth.rest.api.spring.model;

import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;

/**
 * Class representing PowerAuth authentication context.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class AuthenticationContext {

    private boolean isValid;
    private Integer remainingAttempts;
    private PowerAuthSignatureTypes signatureType;

    /**
     * Get whether PowerAuth authentication succeeded.
     * @return Whether PowerAuth authentication succeeded.
     */
    public boolean isValid() {
        return isValid;
    }

    /**
     * Set whether PowerAuth authentication succeeded.
     * @param signatureValid Whether PowerAuth authentication succeeded.
     */
    public void setValid(boolean signatureValid) {
        this.isValid = signatureValid;
    }

    /**
     * Get remaining attempts for signature verification before activation gets blocked.
     * @return Remaining attempts for signature verification before activation gets blocked.
     */
    public Integer getRemainingAttempts() {
        return remainingAttempts;
    }

    /**
     * Set remaining attempts for signature verification before activation gets blocked.
     * @param remainingAttempts Remaining attempts for signature verification before activation gets blocked.
     */
    public void setRemainingAttempts(Integer remainingAttempts) {
        this.remainingAttempts = remainingAttempts;
    }

    /**
     * Get PowerAuth signature type.
     * @return PowerAuth signature type.
     */
    public PowerAuthSignatureTypes getSignatureType() {
        return signatureType;
    }

    /**
     * Set PowerAuth signature type.
     * @param signatureType PowerAuth signature type.
     */
    public void setSignatureType(PowerAuthSignatureTypes signatureType) {
        this.signatureType = signatureType;
    }

}