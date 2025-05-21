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
package io.getlime.security.powerauth.rest.api.model.request;

import io.getlime.security.powerauth.rest.api.model.entity.ActivationType;
import lombok.Data;

import java.util.Map;

/**
 * Request object for activation layer 1.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@Data
public class ActivationLayer1Request {

    /**
     * Activation type.
     */
    private ActivationType type;

    /**
     * Identity attributes.
     */
    private Map<String, String> identityAttributes;

    /**
     * Custom attributes.
     */
    private Map<String, Object> customAttributes;

    /**
     * Encrypted activation data.
     */
    private EciesEncryptedRequest activationData;
}
