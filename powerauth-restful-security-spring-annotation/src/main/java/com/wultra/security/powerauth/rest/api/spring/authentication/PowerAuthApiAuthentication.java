/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2018 Wultra s.r.o.
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
package com.wultra.security.powerauth.rest.api.spring.authentication;

import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import com.wultra.security.powerauth.http.PowerAuthHttpHeader;
import com.wultra.security.powerauth.rest.api.spring.model.AuthenticationContext;

import java.util.List;

/**
 * Interface for PowerAuth API authentication object used between intermediate server
 * application (such as mobile banking API) and core systems (such as banking core).
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
public interface PowerAuthApiAuthentication {

    /**
     * Get user ID.
     * @return User ID.
     */
    String getUserId();

    /**
     * Set user ID
     * @param userId User ID
     */
    void setUserId(String userId);

    /**
     * Get activation ID.
     * This method is deprecated, use {@link PowerAuthApiAuthentication#getActivationContext()} instead.
     * @return Activation ID.
     */
    @Deprecated
    String getActivationId();

    /**
     * Set activation ID.
     * This method is deprecated, use {@link PowerAuthApiAuthentication#getActivationContext()} instead.
     * @param activationId Activation ID.
     */
    @Deprecated
    void setActivationId(String activationId);

    /**
     * Get related application ID.
     * @return Application ID.
     */
    String getApplicationId();

    /**
     * Set related application ID.
     * @param id Application ID.
     */
    void setApplicationId(String id);

    /**
     * Get application roles.
     * @return Application roles.
     */
    List<String> getApplicationRoles();

    /**
     * Set application roles.
     * @param applicationRoles Application roles.
     */
    void setApplicationRoles(List<String> applicationRoles);

    /**
     * Get activation flags.
     * This method is deprecated, use {@link PowerAuthApiAuthentication#getActivationContext()} instead.
     * @return Activation flags.
     */
    @Deprecated
    List<String> getActivationFlags();

    /**
     * Set activation flags.
     * This method is deprecated, use {@link PowerAuthApiAuthentication#getActivationContext()} instead.
     * @param activationFlags Activation flags.
     */
    @Deprecated
    void setActivationFlags(List<String> activationFlags);

    /**
     * Return authentication factors related to the signature that was used to produce
     * this authentication object.
     * This method is deprecated, use {@link PowerAuthApiAuthentication#getAuthenticationContext()} ()} instead.
     * @return Signature type (signature factors).
     */
    @Deprecated
    PowerAuthSignatureTypes getSignatureFactors();

    /**
     * Set authentication factors related to the signature that was used to produce
     * this authentication object.
     * This method is deprecated, use {@link PowerAuthApiAuthentication#getAuthenticationContext()} ()} instead.
     * @param factors Signature type (signature factors).
     */
    @Deprecated
    void setSignatureFactors(PowerAuthSignatureTypes factors);

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
     * @return PowerAuth protocol version.
     */
    String getVersion();

    /**
     * Set PowerAuth protocol version.
     * @param version PowerAuth protocol version.
     */
    void setVersion(String version);

    /**
     * Get the PowerAuth HTTP header.
     * @return PowerAuth HTTP header.
     */
    PowerAuthHttpHeader getHttpHeader();

    /**
     * Set the PowerAuth HTTP header.
     * @param httpHeader PowerAuth HTTP header.
     */
    void setHttpHeader(PowerAuthHttpHeader httpHeader);

    /**
     * Get the activation context.
     * @return Activation context.
     */
    PowerAuthActivation getActivationContext();

    /**
     * Set the activation context.
     * @param activationContext Activation context.
     */
    void setActivationContext(PowerAuthActivation activationContext);

}
