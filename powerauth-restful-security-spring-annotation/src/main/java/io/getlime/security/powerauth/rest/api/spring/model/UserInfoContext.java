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
package io.getlime.security.powerauth.rest.api.spring.model;

import io.getlime.security.powerauth.rest.api.model.entity.UserInfoStage;
import lombok.Builder;
import lombok.Data;

/**
 * Class for passing the context attributes to user info provider.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
@Builder
public class UserInfoContext {

    /**
     * Information about where the user info is requested from.
     */
    private UserInfoStage stage;

    /**
     * User ID.
     */
    private String userId;

    /**
     * Activation ID.
     */
    private String activationId;

    /**
     * Application ID.
     */
    private String applicationId;

}
