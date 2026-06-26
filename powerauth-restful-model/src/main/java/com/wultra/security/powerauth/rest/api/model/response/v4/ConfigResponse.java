/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2026 Wultra s.r.o.
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
package com.wultra.security.powerauth.rest.api.model.response.v4;

import com.wultra.security.powerauth.rest.api.model.entity.ConfigItem;

import java.util.ArrayList;
import java.util.List;

/**
 * Response object for the secure configuration endpoints (V4).
 *
 * @param config Configuration items.
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public record ConfigResponse(List<ConfigItem> config) {

    public ConfigResponse {
        config = config == null ? new ArrayList<>() : config;
    }

}

