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

import java.io.Serial;

/**
 * Exception related to application configuration.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
public class PowerAuthApplicationConfigurationException extends Exception {

    @Serial
    private static final long serialVersionUID = 8677977961740746599L;

    /**
     * No-arg constructor.
     */
    public PowerAuthApplicationConfigurationException() {
        super();
    }

    /**
     * Constructor with a custom error message.
     * @param message Error message.
     */
    public PowerAuthApplicationConfigurationException(String message) {
        super(message);
    }

    /**
     * Constructor with a cause.
     * @param cause Error cause.
     */
    public PowerAuthApplicationConfigurationException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructor with a message and cause.
     * @param message Error message.
     * @param cause Error cause.
     */
    public PowerAuthApplicationConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
}
