/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2019 Wultra s.r.o.
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
package com.wultra.security.powerauth.rest.api.model.exception;

import com.wultra.core.rest.model.base.response.ObjectResponse;

/**
 * Class representing recovery error response.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class RecoveryErrorResponse extends ObjectResponse<RecoveryError> {

    /**
     * Constructor with error code, error message and current recovery PUK index.
     * @param code Error code.
     * @param message Error message.
     * @param currentRecoveryPukIndex Current recovery PUK index.
     */
    public RecoveryErrorResponse(String code, String message, Integer currentRecoveryPukIndex) {
        super("ERROR", new RecoveryError(code, message, currentRecoveryPukIndex));
    }

    /**
     * Constructor with error code, Throwable and current recovery PUK index.
     * @param code Error code.
     * @param t Throwable.
     * @param currentRecoveryPukIndex Current recovery PUK index.
     */
    public RecoveryErrorResponse(String code, Throwable t, Integer currentRecoveryPukIndex) {
        super("ERROR", new RecoveryError(code, t != null ? t.getMessage() : null, currentRecoveryPukIndex));
    }

}
