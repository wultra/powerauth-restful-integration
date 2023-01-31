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
package io.getlime.security.powerauth.rest.api.spring.provider;

import io.getlime.security.powerauth.rest.api.model.entity.UserInfoStage;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthUserInfoException;
import io.getlime.security.powerauth.rest.api.spring.model.UserInfoContext;

import javax.annotation.Nonnull;
import java.util.Map;

/**
 * Interface for bean that provides information about a given user.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
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
    default boolean returnUserInfoDuringStage(@Nonnull UserInfoContext context) {
        return UserInfoStage.USER_INFO_ENDPOINT == context.getStage();
    }

    /**
     * Fetch claims (as used, for example, in JWT) for a given user ID. The map may, but does not have to include claims
     * "sub", "jti", and "iat". If these claims are set, they will override values which were automatically inferred from the
     * authentication object provided by PowerAuth stack. This may be helpful, for example, to anonymize the user ID
     * contained in the "sub" claim.
     *
     * @param context User info context object.
     * @return Map of claims obtained for a given user ID.
     */
    default Map<String, Object> fetchUserClaimsForUserId(UserInfoContext context) throws PowerAuthUserInfoException {
        return null;
    }

}
