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
package com.wultra.security.powerauth.rest.api.spring.converter;

import com.wultra.security.powerauth.rest.api.spring.model.ActivationStatus;
import org.springframework.stereotype.Component;

/**
 * Converter class for conversions of activation status.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
public class ActivationStatusConverter {

    /**
     * Convert {@link ActivationStatus} from a {@link com.wultra.security.powerauth.client.model.enumeration.ActivationStatus} value.
     * @param activationStatus Activation status from PowerAuth client model.
     * @return Activation status from Restful integration model.
     */
    public ActivationStatus convert(com.wultra.security.powerauth.client.model.enumeration.ActivationStatus activationStatus) {
        if (activationStatus == null) {
            return null;
        }

        return switch (activationStatus) {
            case CREATED -> ActivationStatus.CREATED;
            case PENDING_COMMIT -> ActivationStatus.PENDING_COMMIT;
            case ACTIVE -> ActivationStatus.ACTIVE;
            case BLOCKED -> ActivationStatus.BLOCKED;
            case REMOVED -> ActivationStatus.REMOVED;
        };
    }

    /**
     * Convert {@link com.wultra.security.powerauth.client.model.enumeration.ActivationStatus} from an {@link ActivationStatus} value.
     * @param activationStatus Activation status from Restful integration model.
     * @return Activation status from PowerAuth client model.
     */
    public com.wultra.security.powerauth.client.model.enumeration.ActivationStatus convert(ActivationStatus activationStatus) {
        if (activationStatus == null) {
            return null;
        }

        return switch (activationStatus) {
            case CREATED -> com.wultra.security.powerauth.client.model.enumeration.ActivationStatus.CREATED;
            case PENDING_COMMIT -> com.wultra.security.powerauth.client.model.enumeration.ActivationStatus.PENDING_COMMIT;
            case ACTIVE -> com.wultra.security.powerauth.client.model.enumeration.ActivationStatus.ACTIVE;
            case BLOCKED -> com.wultra.security.powerauth.client.model.enumeration.ActivationStatus.BLOCKED;
            case REMOVED -> com.wultra.security.powerauth.client.model.enumeration.ActivationStatus.REMOVED;
        };
    }

}
