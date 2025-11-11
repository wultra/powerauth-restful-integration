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
package com.wultra.security.powerauth.rest.api.spring.controller.v4;

import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.rest.api.model.request.v4.ServerStatusRequest;
import com.wultra.security.powerauth.rest.api.model.response.v4.ServerStatusResponse;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthStatusException;
import com.wultra.security.powerauth.rest.api.spring.service.v4.ServerStatusService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller that provides application status information.
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>4.0</li>
 * </ul>
 *
 * @author Petr Dvorak, petr@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@RestController("serverStatusControllerV4")
@RequestMapping("pa/v4")
@AllArgsConstructor
@Slf4j
public class ServerStatusController {

    private final ServerStatusService serverStatusService;

    /**
     * Obtain server status.
     * @return Server status.
     * @throws PowerAuthStatusException In case application query fails.
     */
    @PostMapping("status")
    public ObjectResponse<ServerStatusResponse> getServerStatus(@RequestBody ObjectRequest<ServerStatusRequest> request) throws PowerAuthStatusException {
        return new ObjectResponse<>(serverStatusService.getServerStatus(request.getRequestObject()));
    }

}
