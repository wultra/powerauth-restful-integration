/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2023 Wultra s.r.o.
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
package io.getlime.security.powerauth.rest.api.model.entity;

/**
 * Information about where the user info is requested from, i.e., during the activation, or via a separate user info
 * endpoint.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public enum UserInfoStage {

    /**
     * The user info was requested from the activation process carried out via activation code.
     */
    ACTIVATION_PROCESS_ACTIVATION_CODE,

    /**
     * The user info was requested from the activation process carried out via custom attributes.
     */
    ACTIVATION_PROCESS_CUSTOM,

    /**
     * The user info was requested from the activation process carried out via recovery codes.
     */
    ACTIVATION_PROCESS_RECOVERY,

    /**
     * The user info was requested from the user info endpoint.
     */
    USER_INFO_ENDPOINT

}
