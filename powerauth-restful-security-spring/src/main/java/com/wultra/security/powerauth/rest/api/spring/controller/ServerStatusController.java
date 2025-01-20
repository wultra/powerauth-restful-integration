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
package com.wultra.security.powerauth.rest.api.spring.controller;

import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.rest.api.model.response.ServerStatusResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.info.BuildProperties;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;

/**
 * Controller that provides a user information.
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 *     <li>3.1</li>
 *     <li>3.2</li>
 *     <li>3.3</li>
 * </ul>
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@RestController
@RequestMapping("pa/v3")
@Slf4j
public class ServerStatusController {

    private BuildProperties buildProperties;

    @Autowired(required = false)
    public void setBuildProperties(BuildProperties buildProperties) {
        this.buildProperties = buildProperties;
    }

    /**
     * Obtain server status.
     * @return Server status.
     */
    @PostMapping("status")
    public ObjectResponse<ServerStatusResponse> getServerStatus() {
        final long serverTime = new Date().getTime();
        final String version;
        final String name;
        if (buildProperties != null) {
            version = buildProperties.getVersion();
            name = buildProperties.getName();
        } else {
            name = "UNKNOWN";
            version = "UNKNOWN";
        }
        final ServerStatusResponse.Application application = new ServerStatusResponse.Application(name, version);
        final ServerStatusResponse response = new ServerStatusResponse(serverTime, application);
        return new ObjectResponse<>(response);
    }

}
