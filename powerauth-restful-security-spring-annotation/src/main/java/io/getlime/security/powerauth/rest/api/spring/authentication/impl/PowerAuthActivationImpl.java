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
package io.getlime.security.powerauth.rest.api.spring.authentication.impl;

import io.getlime.security.powerauth.rest.api.spring.authentication.PowerAuthActivation;
import io.getlime.security.powerauth.rest.api.spring.model.ActivationStatus;
import io.getlime.security.powerauth.rest.api.spring.model.AuthenticationContext;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Class representing PowerAuth activation detail in context of signature verification.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class PowerAuthActivationImpl implements PowerAuthActivation, Serializable {

    private static final long serialVersionUID = -2171754572617130041L;

    /**
     * User ID.
     */
    private String userId;

    /**
     * Activation ID.
     */
    private String activationId;

    /**
     * Activation status.
     */
    private ActivationStatus activationStatus;

    /**
     * Activation blocked reason.
     */
    private String blockedReason;

    /**
     * Activation flags.
     */
    private List<String> activationFlags;

    /**
     * PowerAuth authentication context.
     */
    private AuthenticationContext authenticationContext;

    /**
     * PowerAuth version.
     */
    private String version;

    @Override
    public String getUserId() {
        return userId;
    }

    @Override
    public void setUserId(String userId) {
        this.userId = userId;
    }

    @Override
    public String getActivationId() {
        return activationId;
    }

    @Override
    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    @Override
    public ActivationStatus getActivationStatus() {
        return activationStatus;
    }

    @Override
    public void setActivationStatus(ActivationStatus activationStatus) {
        this.activationStatus = activationStatus;
    }

    @Override
    public String getBlockedReason() {
        return blockedReason;
    }

    @Override
    public void setBlockedReason(String blockedReason) {
        this.blockedReason = blockedReason;
    }

    @Override
    public List<String> getActivationFlags() {
        return activationFlags;
    }

    @Override
    public void setActivationFlags(List<String> activationFlags) {
        if (activationFlags == null) {
            this.activationFlags = null;
        } else {
            this.activationFlags = new ArrayList<>(activationFlags);
        }
    }

    @Override
    public AuthenticationContext getAuthenticationContext() {
        return authenticationContext;
    }

    @Override
    public void setAuthenticationContext(AuthenticationContext authenticationContext) {
        this.authenticationContext = authenticationContext;
    }

    @Override
    public String getVersion() {
        return version;
    }

    @Override
    public void setVersion(String version) {
        this.version = version;
    }

}