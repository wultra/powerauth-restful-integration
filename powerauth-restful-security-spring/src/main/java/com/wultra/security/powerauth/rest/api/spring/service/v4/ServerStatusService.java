/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2025 Wultra s.r.o.
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
package com.wultra.security.powerauth.rest.api.spring.service.v4;


import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.response.LookupApplicationByAppKeyResponse;
import com.wultra.security.powerauth.client.model.response.v4.GetApplicationDetailResponse;
import com.wultra.security.powerauth.client.v4.PowerAuthClient;
import com.wultra.security.powerauth.rest.api.model.request.v4.ServerStatusRequest;
import com.wultra.security.powerauth.rest.api.model.response.v4.ServerStatusResponse;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthStatusException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.info.BuildProperties;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;

/**
 * Service implementing server status functionality.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>4.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@Service("serverStatusServiceV4")
@Slf4j
public class ServerStatusService {

    private final PowerAuthClient powerAuthClient;
    private BuildProperties buildProperties;

    /**
     * Service constructor.
     * @param powerAuthClient PowerAuth client.
     */
    @Autowired
    public ServerStatusService(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    /**
     * Set build properties.
     * @param buildProperties Build properties.
     */
    @Autowired(required = false)
    public void setBuildProperties(BuildProperties buildProperties) {
        this.buildProperties = buildProperties;
    }

    /**
     * Fetch server status with an optional supported algorithm query.
     * @param request Server status request.
     * @return Server status response.
     * @throws PowerAuthStatusException In case application query fails.
     */
    public ServerStatusResponse getServerStatus(ServerStatusRequest request) throws PowerAuthStatusException {
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

        final List<String> supportedAlgorithms;
        try {
            if (request != null && request.applicationKey() != null) {
                final LookupApplicationByAppKeyResponse appResponse = powerAuthClient.lookupApplicationByAppKey(request.applicationKey());
                final GetApplicationDetailResponse detailResponse = powerAuthClient.getApplicationDetail(appResponse.getApplicationId());
                supportedAlgorithms = detailResponse.getSupportedAlgorithms();
            } else {
                supportedAlgorithms = null;
            }
            return new ServerStatusResponse(serverTime, supportedAlgorithms, application);
        } catch (PowerAuthClientException e) {
            logger.warn("Application query failed, error: {}", e.getMessage());
            logger.debug(e.getMessage(), e);
            throw new PowerAuthStatusException();
        }
    }

}
