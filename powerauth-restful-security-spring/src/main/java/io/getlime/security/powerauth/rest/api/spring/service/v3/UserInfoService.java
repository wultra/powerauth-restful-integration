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

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.response.GetActivationStatusResponse;
import io.getlime.security.powerauth.rest.api.model.entity.UserInfoStage;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthUserInfoException;
import io.getlime.security.powerauth.rest.api.spring.model.UserInfoContext;
import io.getlime.security.powerauth.rest.api.spring.provider.UserInfoProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Map;

/**
 * Service for obtaining user info as claims map.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Service
public class UserInfoService {

    private UserInfoProvider userInfoProvider;
    private final PowerAuthClient powerAuthClient;

    @Autowired
    public UserInfoService(PowerAuthClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    /**
     * Setter with optional user info provider bean.
     * @param userInfoProvider User info provider.
     */
    @Autowired(required = false)
    public void setActivationProvider(UserInfoProvider userInfoProvider) {
        this.userInfoProvider = userInfoProvider;
    }

    /**
     * Fetch user info as a map of claims. Returns empty map by default, i.e., if user info provider is not registered.
     *
     * @param activationId Activation ID.
     * @return Map of claims.
     * @throws PowerAuthUserInfoException In case there is an error while fetching claims.
     */
    public Map<String, Object> fetchUserClaimsByActivationId(String activationId) throws PowerAuthUserInfoException {
        try {

            if (userInfoProvider == null) {
                return Collections.emptyMap();
            }

            // Fetch activation details
            final GetActivationStatusResponse activationStatusResponse = powerAuthClient.getActivationStatus(activationId);
            final String userId = activationStatusResponse.getUserId();
            final String applicationId = activationStatusResponse.getApplicationId();
            final ActivationStatus activationStatus = activationStatusResponse.getActivationStatus();

            if (ActivationStatus.ACTIVE != activationStatus) { // only allow active state for now
                throw new PowerAuthUserInfoException("Invalid activation status: " + activationStatus + ", for activation: " + activationId);
            }

            final UserInfoContext userInfoContext = UserInfoContext.builder()
                    .stage(UserInfoStage.USER_INFO_ENDPOINT)
                    .userId(userId)
                    .activationId(activationId)
                    .applicationId(applicationId)
                    .build();
            if (userInfoProvider.shouldReturnUserInfo(userInfoContext)) {
                return userInfoProvider.fetchUserClaimsForUserId(userInfoContext);
            } else {
                return Collections.emptyMap();
            }

        } catch (PowerAuthClientException ex) {
            throw new PowerAuthUserInfoException("Fetching user claims failed, activation ID: " + activationId, ex);
        }
    }

}
