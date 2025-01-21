/*
 * PowerAuth Enrollment Server
 * Copyright (C) 2022 Wultra s.r.o.
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
package com.wultra.security.powerauth.rest.api.spring.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration of interceptors.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Configuration
@ConditionalOnProperty(
        value = "powerauth.service.correlation-header.enabled",
        havingValue = "true"
)
public class CorrelationHeaderConfiguration {

    @Value("${powerauth.service.correlation-header.name:X-Correlation-ID}")
    private String correlationHeaderName;

    /**
     * Get correlation header name.
     * @return Correlation header name.
     */
    public String getCorrelationHeaderName() {
        return correlationHeaderName;
    }
}