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
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.v3.ActivationStatus;
import com.wultra.security.powerauth.client.v3.GetActivationStatusResponse;
import io.getlime.security.powerauth.rest.api.model.entity.UserInfoStage;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthUserInfoException;
import io.getlime.security.powerauth.rest.api.spring.model.UserInfoContext;
import io.getlime.security.powerauth.rest.api.spring.model.UserInfoContextBuilder;
import io.getlime.security.powerauth.rest.api.spring.provider.UserInfoProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    private static final Logger logger = LoggerFactory.getLogger(UserInfoService.class);

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
     * Fetch user info as a map of claims.
     *
     * @param activationId Activation ID.
     * @return Map of claims.
     * @throws PowerAuthUserInfoException In case there is an error while fetching claims.
     */
    public Map<String, Object> fetchUserClaimsByActivationId(String activationId) throws PowerAuthUserInfoException {
        try {
            // Fetch activation details
            final GetActivationStatusResponse activationStatusResponse = powerAuthClient.getActivationStatus(activationId);
            final String userId = activationStatusResponse.getUserId();
            final String applicationId = activationStatusResponse.getApplicationId();
            final ActivationStatus activationStatus = activationStatusResponse.getActivationStatus();

            if (ActivationStatus.ACTIVE != activationStatus) { // only allow active state for now
                throw new PowerAuthUserInfoException("Invalid activation status: " + activationStatus + ", for activation: " + activationId);
            }

            final Map<String, Object> map = new LinkedHashMap<>();
            map.put("sub", userId);
            map.put("jti", UUID.randomUUID().toString());
            map.put("iat", Instant.now().getEpochSecond());

            if (userInfoProvider != null) {
                final UserInfoContext userInfoContext = new UserInfoContextBuilder()
                        .setStage(UserInfoStage.USER_INFO_ENDPOINT)
                        .setUserId(userId)
                        .setActivationId(activationId)
                        .setApplicationId(applicationId)
                        .build();
                if (userInfoProvider.returnUserInfoDuringStage(userInfoContext)) {
                    final Map<String, Object> claims = userInfoProvider.fetchUserClaimsForUserId(userInfoContext);
                    if (claims != null) {
                        map.putAll(claims);
                    }
                }
            }

            return map;
        } catch (PowerAuthClientException ex) {
            logger.warn("Fetching user claims failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthUserInfoException(ex);
        }
    }

}
