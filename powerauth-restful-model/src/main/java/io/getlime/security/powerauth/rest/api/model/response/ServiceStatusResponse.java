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
package io.getlime.security.powerauth.rest.api.model.response;

import lombok.Data;

import java.util.Date;

/**
 * Response object for a system status call.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
public class ServiceStatusResponse {

    /**
     * The application name.
     */
    private String applicationName;

    /**
     * The application display name.
     */
    private String applicationDisplayName;

    /**
     * Application environment name.
     */
    private String applicationEnvironment;

    /**
     * Version.
     */
    private String version;

    /**
     * Build time.
     */
    private Date buildTime;

    /**
     * Current timestamp.
     */
    private Date timestamp;

}
