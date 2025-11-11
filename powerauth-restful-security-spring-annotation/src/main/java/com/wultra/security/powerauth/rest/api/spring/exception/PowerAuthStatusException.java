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
package com.wultra.security.powerauth.rest.api.spring.exception;

import java.io.Serial;

/**
 * Exception for endpoints related to the server status endpoint.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class PowerAuthStatusException extends Exception {

    @Serial
    private static final long serialVersionUID = 4498282154685905927L;

    private static final String DEFAULT_CODE = "ERR_STATUS";
    private static final String DEFAULT_ERROR = "POWER_AUTH_STATUS_ERROR";

    /**
     * Default constructor.
     */
    public PowerAuthStatusException() {
        super(DEFAULT_ERROR);
    }

    /**
     * Constructor with a custom error message.
     * @param message Error message.
     */
    public PowerAuthStatusException(String message) {
        super(message);
    }

    /**
     * Constructor with a cause.
     * @param cause Error cause.
     */
    public PowerAuthStatusException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructor with a message and cause.
     * @param message Error message.
     * @param cause Error cause.
     */
    public PowerAuthStatusException(String message, Throwable cause) {
        super(message, cause);
    }


    /**
     * Get default error code, used for example in the REST response.
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
