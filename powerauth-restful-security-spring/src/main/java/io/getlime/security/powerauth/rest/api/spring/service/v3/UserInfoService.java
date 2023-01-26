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
package io.getlime.security.powerauth.rest.api.spring.service.v3;

import io.getlime.security.powerauth.rest.api.model.entity.UserInfoStage;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthUserInfoException;
import io.getlime.security.powerauth.rest.api.spring.provider.UserInfoProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Service for obtaining user info as claims map.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service
public class UserInfoService {

    private UserInfoProvider userInfoProvider;

    /**
     * Setter with optional user info provider bean.
     * @param userInfoProvider User info provider.
     */
    @Autowired(required = false)
    public void setActivationProvider(UserInfoProvider userInfoProvider) {
        this.userInfoProvider = userInfoProvider;
    }

    /**
     * Fetch user info as a map of claims.
     *
     * @param userId User ID.
     * @param activationId Activation ID.
     * @param applicationId Application ID.
     * @return Map of claims.
     * @throws PowerAuthUserInfoException In case there is an error while fetching claims.
     */
    public Map<String, Object> fetchUserClaimsByUserId(String userId, String activationId, String applicationId) throws PowerAuthUserInfoException {
        final Map<String, Object> map = new LinkedHashMap<>();
        map.put("sub", userId);
        map.put("jti", UUID.randomUUID().toString());
        map.put("iat", Instant.now().getEpochSecond());

        if (userInfoProvider != null) {
            if (userInfoProvider.returnUserInfoDuringStage(UserInfoStage.USER_INFO_ENDPOINT, userId, activationId, applicationId)) {
                final Map<String, Object> claims = userInfoProvider.fetchUserClaimsForUserId(UserInfoStage.USER_INFO_ENDPOINT, userId, activationId, applicationId);
                if (claims != null) {
                    for (String key : claims.keySet()) {
                        map.put(key, claims.get(key));
                    }
                }
            }
        }

        return map;
    }

}
