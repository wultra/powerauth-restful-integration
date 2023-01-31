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

/**
 * Builder for the user info context class.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class UserInfoContextBuilder {

    private UserInfoStage stage;
    private String userId;
    private String activationId;
    private String applicationId;

    /**
     * Setter for stage.
     * @param stage Stage.
     * @return This.
     */
    public UserInfoContextBuilder setStage(UserInfoStage stage) {
        this.stage = stage;
        return this;
    }

    /**
     * Set user ID.
     * @param userId User ID.
     * @return This.
     */
    public UserInfoContextBuilder setUserId(String userId) {
        this.userId = userId;
        return this;
    }

    /**
     * Set activation ID.
     * @param activationId Activation ID.
     * @return This.
     */
    public UserInfoContextBuilder setActivationId(String activationId) {
        this.activationId = activationId;
        return this;
    }

    /**
     * Set application ID.
     * @param applicationId Application ID.
     * @return This.
     */
    public UserInfoContextBuilder setApplicationId(String applicationId) {
        this.applicationId = applicationId;
        return this;
    }

    public UserInfoContext build() {
        return new UserInfoContext(stage, userId, activationId, applicationId);
    }
}