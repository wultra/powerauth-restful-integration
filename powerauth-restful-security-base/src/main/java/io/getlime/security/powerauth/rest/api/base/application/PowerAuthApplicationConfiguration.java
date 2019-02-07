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
package io.getlime.security.powerauth.rest.api.base.application;

import java.util.Map;

/**
 * Interface providing method for PowerAuth behavior high-level customization.
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
public interface PowerAuthApplicationConfiguration {

    /**
     * Check if a given application key is allowed in given server instance. Default and suggested behavior
     * is to simply return true, unless for some reason given application key must be restricted while still
     * being "supported" in the PowerAuth server database.
     * @param applicationKey Application key
     * @return True if the application key is allowed, false otherwise.
     */
    boolean isAllowedApplicationKey(String applicationKey);

    /**
     * In order to minimize number of up-front request, /pa/activation/status end-point may return
     * any custom state-less object with an information about the service (such as current timestamp,
     * service outage info, etc.). Default implementation may simply return null.
     * @return Custom object with state-less information about the API server status.
     */
    Map<String, Object> statusServiceCustomObject();

}
