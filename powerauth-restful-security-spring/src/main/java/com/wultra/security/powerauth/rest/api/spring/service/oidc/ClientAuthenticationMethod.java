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
package com.wultra.security.powerauth.rest.api.spring.service.oidc;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * OIDC client authentication methods.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
enum ClientAuthenticationMethod {

    @JsonProperty("client_secret_basic")
    CLIENT_SECRET_BASIC,

    @JsonProperty("client_secret_post")
    CLIENT_SECRET_POST

}
