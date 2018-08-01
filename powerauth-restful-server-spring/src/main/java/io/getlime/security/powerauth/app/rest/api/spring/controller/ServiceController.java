/*
 * Copyright 2016 Lime - HighTech Solutions s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.getlime.security.powerauth.app.rest.api.spring.controller;

import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.app.rest.api.spring.configuration.PowerAuthWebServiceConfiguration;
import io.getlime.security.powerauth.rest.api.model.response.ServiceStatusResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.info.BuildProperties;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Date;

/**
 * Class representing controller used for service and maintenance purpose.
 *
 * @author Roman Strobl, roman.strobl@lime-company.eu
 */
@Controller
@RequestMapping(value = "/api/service")
public class ServiceController {

    private final PowerAuthWebServiceConfiguration powerAuthWebServiceConfiguration;
    private BuildProperties buildProperties;

    @Autowired
    public ServiceController(PowerAuthWebServiceConfiguration powerAuthWebServiceConfiguration) {
        this.powerAuthWebServiceConfiguration = powerAuthWebServiceConfiguration;
    }

    @Autowired(required = false)
    public void setBuildProperties(BuildProperties buildProperties) {
        this.buildProperties = buildProperties;
    }

    /**
     * Controller resource with system information.
     * @return System status info.
     */
    @RequestMapping(value = "status", method = RequestMethod.GET)
    public @ResponseBody ObjectResponse<ServiceStatusResponse> getServiceStatus() {
        ServiceStatusResponse response = new ServiceStatusResponse();
        response.setApplicationName(powerAuthWebServiceConfiguration.getApplicationName());
        response.setApplicationDisplayName(powerAuthWebServiceConfiguration.getApplicationDisplayName());
        response.setApplicationEnvironment(powerAuthWebServiceConfiguration.getApplicationEnvironment());
        if (buildProperties != null) {
            response.setVersion(buildProperties.getVersion());
            response.setBuildTime(Date.from(buildProperties.getTime()));
        }
        response.setTimestamp(new Date());
        return new ObjectResponse<>(response);
    }
}
