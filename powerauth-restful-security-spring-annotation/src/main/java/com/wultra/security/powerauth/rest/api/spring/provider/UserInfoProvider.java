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
package com.wultra.security.powerauth.rest.api.spring.provider;

import com.wultra.core.annotations.PublicSpi;
import com.wultra.security.powerauth.rest.api.model.entity.UserInfoStage;
import com.wultra.security.powerauth.rest.api.spring.model.UserInfoContext;
import jakarta.annotation.Nonnull;

import java.util.Collections;
import java.util.Map;

/**
 * Interface for bean that provides information about a given user.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@PublicSpi
public interface UserInfoProvider {

    /**
     * Determine if the user info should be returned during the provided stage. By default, the user info is only
     * available via a specialized <code>/pa/v3/user/info</code> endpoint. By overriding this method, the user info claims
     * might be also returned in the activation response body (inside the outer-encrypted layer).
     *
     * @param context User info context object.
     * @return True if the user info should be returned during the activation, false otherwise (user info is only
     *         returned in the separate user info endpoint).
     */
    default boolean shouldReturnUserInfo(@Nonnull UserInfoContext context) {
        return UserInfoStage.USER_INFO_ENDPOINT == context.getStage();
    }

    /**
     * Return claims (as used, for example, in JWT) for a given user ID. Default implementation returns minimal claims.
     *
     * @param context User info context object.
     * @return Map of claims obtained for a given user ID.
     */
    default Map<String, Object> fetchUserClaimsForUserId(@Nonnull UserInfoContext context) {
        return Collections.emptyMap();
    }
}
