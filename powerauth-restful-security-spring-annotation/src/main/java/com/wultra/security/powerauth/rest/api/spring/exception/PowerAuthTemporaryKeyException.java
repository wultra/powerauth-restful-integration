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
package com.wultra.security.powerauth.rest.api.spring.exception;

/**
 * Exception raised in case PowerAuth fails to return temporary keys.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class PowerAuthTemporaryKeyException extends Exception {

    private static final String DEFAULT_CODE = "ERR_TEMPORARY_KEY";
    private static final String DEFAULT_ERROR = "POWER_AUTH_TEMPORARY_KEY_FAILURE";

    /**
     * Default constructor.
     */
    public PowerAuthTemporaryKeyException() {
        super(DEFAULT_ERROR);
    }

    /**
     * Get the default error code, used for example in REST response.
     * @return Default error code.
     */
    public String getDefaultCode() {
        return DEFAULT_CODE;
    }

    /**
     * Get default error message, used for example in the REST response.
     * @return Default error message.
     */
    public String getDefaultError() {
        return DEFAULT_ERROR;
    }

}
