/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2021 Wultra s.r.o.
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
package io.getlime.security.powerauth.rest.api.spring.authentication;

import io.getlime.security.powerauth.rest.api.spring.model.ActivationStatus;
import io.getlime.security.powerauth.rest.api.spring.model.AuthenticationContext;

import java.util.List;

/**
 * Interface for obtaining PowerAuth activation detail during signature verification.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public interface PowerAuthActivation {

    /**
     * Get user ID.
     * @return User ID.
     */
    String getUserId();

    /**
     * Set user ID.
     * @param userId User ID.
     */
    void setUserId(String userId);

    /**
     * Get activation ID.
     * @return Activation ID.
     */
    String getActivationId();

    /**
     * Set activation ID.
     * @param activationId Activation ID.
     */
    void setActivationId(String activationId);

    /**
     * Get activation status.
     * @return Activation status.
     */
    ActivationStatus getActivationStatus();

    /**
     * Set activation status.
     * @param activationStatus Activation status.
     */
    void setActivationStatus(ActivationStatus activationStatus);

    /**
     * Get the reason why activation was blocked.
     * @return Reason why activation was blocked.
     */
    String getBlockedReason();

    /**
     * Set the reason why activation was blocked.
     * @param blockedReason Reason why activation was blocked.
     */
    void setBlockedReason(String blockedReason);

    /**
     * Get activation flags.
     * @return Activation flags.
     */
    List<String> getActivationFlags();

    /**
     * Set activation flags.
     * @param activationFlags Activation flags.
     */
    void setActivationFlags(List<String> activationFlags);

    /**
     * Get PowerAuth authentication context.
     * @return PowerAuth authentication context.
     */
    AuthenticationContext getAuthenticationContext();

    /**
     * Set PowerAuth authentication context.
      * @param authenticationContext PowerAuth authentication context.
     */
    void setAuthenticationContext(AuthenticationContext authenticationContext);

    /**
     * Get PowerAuth protocol version.
     *
     * @return PowerAuth protocol version.
     */
    String getVersion();

    /**
     * Set PowerAuth protocol version.
     *
     * @param version PowerAuth protocol version.
     */
    void setVersion(String version);

}