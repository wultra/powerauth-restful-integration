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
package com.wultra.security.powerauth.rest.api.spring.annotation;

import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.rest.api.spring.model.ActivationStatus;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation that enables simple integration with PowerAuth authentication.
 *
 * @author Petr Dvorak, petr@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface PowerAuth {

    /**
     * Identifier of the resource URI, usually the "effective" part of the URL, for example
     * "/banking/payment/commit".
     *
     * @return Resource identifier.
     */
    String resourceId();

    /**
     * Types of supported authentication code types. By default, any at least 2FA authentication code type must be specified.
     *
     * @return Supported authentication code types.
     */
    PowerAuthCodeType[] authenticationCodeType() default {
            PowerAuthCodeType.POSSESSION_BIOMETRY,
            PowerAuthCodeType.POSSESSION_KNOWLEDGE,
            PowerAuthCodeType.POSSESSION_KNOWLEDGE_BIOMETRY
    };

    /**
     * Allowed states for verifying authentication. This option allows configuring additional states for use cases
     * when verification is required in other states than ACTIVE.
     * @return Allowed activation states.
     */
    ActivationStatus[] allowedStates() default { ActivationStatus.ACTIVE };

}
