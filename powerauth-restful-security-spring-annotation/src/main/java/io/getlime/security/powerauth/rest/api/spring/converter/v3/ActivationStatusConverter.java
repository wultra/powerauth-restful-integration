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
package io.getlime.security.powerauth.rest.api.spring.converter.v3;

import io.getlime.security.powerauth.rest.api.spring.model.ActivationStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Converter class for conversions of activation status.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Component
public class ActivationStatusConverter {

    private static final Logger logger = LoggerFactory.getLogger(ActivationStatusConverter.class);

    /**
     * Convert {@link ActivationStatus} from a {@link com.wultra.security.powerauth.client.model.enumeration.ActivationStatus} value.
     * @param activationStatus Activation status from PowerAuth client model.
     * @return Activation status from Restful integration model.
     */
    public ActivationStatus convertFrom(com.wultra.security.powerauth.client.model.enumeration.ActivationStatus activationStatus) {
        if (activationStatus == null) {
            return null;
        }

        switch (activationStatus) {
            case CREATED:
                return ActivationStatus.CREATED;

            case PENDING_COMMIT:
                return ActivationStatus.PENDING_COMMIT;

            case ACTIVE:
                return ActivationStatus.ACTIVE;

            case BLOCKED:
                return ActivationStatus.BLOCKED;

            case REMOVED:
                return ActivationStatus.REMOVED;
        }

        return null;
    }

}
