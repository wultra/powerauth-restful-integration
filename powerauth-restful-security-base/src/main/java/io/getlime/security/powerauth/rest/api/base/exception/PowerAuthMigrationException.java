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
package io.getlime.security.powerauth.rest.api.base.exception;

/**
 * Exception raised in case PowerAuth migration fails.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class PowerAuthMigrationException extends Exception {

    private static final long serialVersionUID = -5750221213611810117L;

    private static final String DEFAULT_CODE = "ERR_MIGRATION";
    private static final String DEFAULT_ERROR = "POWER_AUTH_MIGRATION_FAILED";

    /**
     * Default constructor.
     */
    public PowerAuthMigrationException() {
        super(DEFAULT_ERROR);
    }

    /**
     * Constructor with a custom error message.
     * @param message Error message.
     */
    public PowerAuthMigrationException(String message) {
        super(message);
    }

    /**
     * Get the default error code, used for example in REST response.
     * @return Default error code.
     */
    public String getDefaultCode() {
        return DEFAULT_CODE;
    }
}
