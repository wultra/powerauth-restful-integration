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
package com.wultra.security.powerauth.rest.api.spring.model;

import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;

/**
 * Class representing PowerAuth authentication context.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class AuthenticationContext {

    private boolean isValid;
    private Integer remainingAttempts;
    private PowerAuthCodeType authenticationCodeType;

    /**
     * Get whether PowerAuth authentication succeeded.
     * @return Whether PowerAuth authentication succeeded.
     */
    public boolean isValid() {
        return isValid;
    }

    /**
     * Set whether PowerAuth authentication succeeded.
     * @param authenticationValid Whether PowerAuth authentication succeeded.
     */
    public void setValid(boolean authenticationValid) {
        this.isValid = authenticationValid;
    }

    /**
     * Get remaining attempts for authentication code verification before activation gets blocked.
     * @return Remaining attempts for authentication code verification before activation gets blocked.
     */
    public Integer getRemainingAttempts() {
        return remainingAttempts;
    }

    /**
     * Set remaining attempts for authentication code verification before activation gets blocked.
     * @param remainingAttempts Remaining attempts for authentication code verification before activation gets blocked.
     */
    public void setRemainingAttempts(Integer remainingAttempts) {
        this.remainingAttempts = remainingAttempts;
    }

    /**
     * Get PowerAuth authentication code type.
     * @return PowerAuth authentication code type.
     */
    public PowerAuthCodeType getAuthenticationCodeType() {
        return authenticationCodeType;
    }

    /**
     * Set PowerAuth authentication code type.
     * @param authenticationCodeType PowerAuth authentication code type.
     */
    public void setAuthenticationCodeType(PowerAuthCodeType authenticationCodeType) {
        this.authenticationCodeType = authenticationCodeType;
    }

}