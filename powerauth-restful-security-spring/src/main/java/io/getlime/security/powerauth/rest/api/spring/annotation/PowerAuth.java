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
package io.getlime.security.powerauth.rest.api.spring.annotation;

import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation that enables simple integration with PowerAuth Signatures.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface PowerAuth {

    String AUTHENTICATION_OBJECT = "X-PowerAuth-Authentication-Object";

    /**
     * Identifier of the resource URI, usually the "effective" part of the URL, for example
     * "/banking/payment/commit".
     *
     * @return Resource identifier.
     */
    String resourceId();

    /**
     * Types of supported signatures. By default, any at least 2FA signature type must be specified.
     *
     * @return Supported signature types.
     */
    PowerAuthSignatureTypes[] signatureType() default {
            PowerAuthSignatureTypes.POSSESSION_BIOMETRY,
            PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE,
            PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY
    };

}
