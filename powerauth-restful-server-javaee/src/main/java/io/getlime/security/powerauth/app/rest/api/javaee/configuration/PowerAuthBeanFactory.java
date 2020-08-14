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
package io.getlime.security.powerauth.app.rest.api.javaee.configuration;

import io.getlime.security.powerauth.rest.api.base.application.PowerAuthApplicationConfiguration;
import io.getlime.security.powerauth.rest.api.jaxrs.application.DefaultApplicationConfiguration;
import io.getlime.security.powerauth.soap.axis.client.PowerAuthServiceClient;
import org.apache.axis2.AxisFault;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.context.Dependent;
import javax.enterprise.inject.Produces;

/**
 * Class responsible for bean auto-wiring.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Dependent
public class PowerAuthBeanFactory {

    private static final Logger logger = LoggerFactory.getLogger(PowerAuthBeanFactory.class);

    @Produces
    public PowerAuthServiceClient buildClient() {
        try {
            return new PowerAuthServiceClient("http://localhost:8080/powerauth-java-server/soap");
        } catch (AxisFault ex) {
            logger.warn("Failed to build client, error: {}", ex.getMessage());
            logger.debug("Error details", ex);
            return null;
        }
    }

    @Produces
    public PowerAuthApplicationConfiguration buildApplicationConfiguration() {
        return new DefaultApplicationConfiguration();
    }

}
