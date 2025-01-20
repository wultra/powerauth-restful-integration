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
package com.wultra.security.powerauth.rest.api.model.entity;

/**
 * Activation type specifying how activation will be handled.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public enum ActivationType {

    /**
     * Activation via activation code.
     */
    CODE,

    /**
     * Activation via custom credentials.
     * @deprecated Use {@link #DIRECT} instead.
     */
    @Deprecated
    CUSTOM,

    /**
     * Direct activation, alias for {@link #CUSTOM}.
     * The method could be specified, for example {@code OIDC}.
     */
    DIRECT,

    /**
     * Activation via recovery code.
     */
    RECOVERY
}
