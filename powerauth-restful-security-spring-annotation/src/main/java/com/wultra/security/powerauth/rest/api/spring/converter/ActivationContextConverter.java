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

import com.wultra.security.powerauth.client.model.response.GetActivationStatusResponse;
import com.wultra.security.powerauth.rest.api.spring.model.ActivationContext;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;

/**
 * Converter class for conversions of activation context.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
public class ActivationContextConverter {

    private final ActivationStatusConverter activationStatusConverter;

    /**
     * Converter constructor.
     * @param activationStatusConverter Activation status converter.
     */
    public ActivationContextConverter(ActivationStatusConverter activationStatusConverter) {
        this.activationStatusConverter = activationStatusConverter;
    }

    /**
     * Convert new activation context from activation status response.
     *
     * @param source Activation status response.
     * @return Activation context.
     */
    public ActivationContext fromActivationDetailResponse(GetActivationStatusResponse source) {
        final ActivationContext destination = new ActivationContext();
        destination.setActivationId(source.getActivationId());
        destination.setActivationName(source.getActivationName());
        destination.setActivationStatus(activationStatusConverter.convertFrom(source.getActivationStatus()));
        destination.setBlockedReason(source.getBlockedReason());
        destination.setApplicationId(source.getApplicationId());
        destination.setUserId(source.getUserId());
        destination.setVersion(source.getVersion());
        destination.setPlatform(source.getPlatform());
        destination.setDeviceInfo(source.getDeviceInfo());
        destination.setExtras(source.getExtras());
        final List<String> activationFlags = source.getActivationFlags();
        if (activationFlags != null) {
            destination.getActivationFlags().addAll(activationFlags);
        }
        final Date timestampCreated = source.getTimestampCreated();
        if (timestampCreated != null) {
            destination.setTimestampCreated(timestampCreated.toInstant());
        }
        final Date timestampLastUsed = source.getTimestampLastUsed();
        if (timestampLastUsed != null) {
            destination.setTimestampLastUsed(timestampLastUsed.toInstant());
        }
        final Date timestampLastChange = source.getTimestampLastChange();
        if (timestampLastChange != null) {
            destination.setTimestampLastChange(timestampLastChange.toInstant());
        }
        return destination;
    }

}
