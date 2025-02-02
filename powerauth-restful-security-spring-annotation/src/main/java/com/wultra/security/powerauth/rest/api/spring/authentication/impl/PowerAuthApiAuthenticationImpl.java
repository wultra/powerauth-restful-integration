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
package com.wultra.security.powerauth.rest.api.spring.authentication.impl;

import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import com.wultra.security.powerauth.http.PowerAuthHttpHeader;
import com.wultra.security.powerauth.rest.api.spring.authentication.PowerAuthActivation;
import com.wultra.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import com.wultra.security.powerauth.rest.api.spring.model.AuthenticationContext;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * PowerAuth API authentication object used between intermediate server application (such as mobile 
 * banking API) and core systems (such as banking core).
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
public class PowerAuthApiAuthenticationImpl extends AbstractAuthenticationToken implements PowerAuthApiAuthentication, Serializable {

    @Serial
    private static final long serialVersionUID = -3790516505615465445L;

    /**
     * Activation ID.
     */
    private String activationId;

    /**
     * User ID.
     */
    private String userId;

    /**
     * Application ID.
     */
    private String applicationId;

    /**
     * List of application roles.
     */
    private List<String> applicationRoles = new ArrayList<>();

    /**
     * List of activation flags.
     */
    private List<String> activationFlags = new ArrayList<>();

    /**
     * Signature type, representing used authentication factor.
     */
    private PowerAuthSignatureTypes factors;

    /**
     * PowerAuth authentication context.
     */
    private AuthenticationContext authenticationContext;

    /**
     * Signature version.
     */
    private String version;

    /**
     * Reference to the original HTTP header.
     */
    private PowerAuthHttpHeader httpHeader;

    /**
     * PowerAuth activation instance representing activation context.
     */
    private PowerAuthActivation activationContext;

    /**
     * Default constructor
     */
    public PowerAuthApiAuthenticationImpl() {
        super(null);
    }

    /**
     * Constructor for a new PowerAuthApiAuthenticationImpl.
     * @param activationId Activation ID.
     * @param userId User ID.
     * @param applicationId Application ID.
     * @param applicationRoles Application roles.
     * @param activationFlags Activation flags.
     * @param authenticationContext Authentication context.
     */
    public PowerAuthApiAuthenticationImpl(String activationId, String userId, String applicationId, List<String> applicationRoles,
                                          List<String> activationFlags, AuthenticationContext authenticationContext) {
        super(null);
        // Deprecated field, updated for compatibility reason
        this.activationId = activationId;
        this.userId = userId;
        this.applicationId = applicationId;
        if (applicationRoles != null) {
            this.applicationRoles = new ArrayList<>(applicationRoles);
        }
        if (activationFlags != null) {
            // Deprecated field, updated for compatibility reason
            this.activationFlags = new ArrayList<>(activationFlags);
        }
        this.authenticationContext = authenticationContext;
        if (authenticationContext != null) {
            // Deprecated field, updated for compatibility reason
            this.factors = authenticationContext.getSignatureType();
        }
        this.activationContext = new PowerAuthActivationImpl();
        activationContext.setActivationId(activationId);
        activationContext.setUserId(userId);
        activationContext.setActivationFlags(activationFlags);
        activationContext.setAuthenticationContext(authenticationContext);
        activationContext.setVersion(version);
    }

    @Override
    public String getName() {
        return userId;
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("USER"));
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return this.activationId;
    }

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
    public String getApplicationId() {
        return applicationId;
    }

    @Override
    public void setApplicationId(String id) {
        this.applicationId = id;
    }

    @Override
    public List<String> getApplicationRoles() {
        return applicationRoles;
    }

    @Override
    public void setApplicationRoles(List<String> applicationRoles) {
        if (applicationRoles == null) {
            this.applicationRoles = Collections.emptyList();
        } else {
            this.applicationRoles = new ArrayList<>(applicationRoles);
        }
    }

    @Override
    public List<String> getActivationFlags() {
        return activationFlags;
    }

    @Override
    public void setActivationFlags(List<String> activationFlags) {
        if (activationFlags == null) {
            this.activationFlags = Collections.emptyList();
        } else {
            this.activationFlags = new ArrayList<>(activationFlags);
        }
    }

    @Override
    public PowerAuthSignatureTypes getSignatureFactors() {
        return factors;
    }

    @Override
    public void setSignatureFactors(PowerAuthSignatureTypes factors) {
        this.factors = factors;
    }

    @Override
    public AuthenticationContext getAuthenticationContext() {
        return authenticationContext;
    }

    @Override
    public void setAuthenticationContext(AuthenticationContext authenticationContext) {
        this.authenticationContext = authenticationContext;
        if (authenticationContext != null) {
            // Update deprecated signatureFactors to ensure compatibility
            setSignatureFactors(authenticationContext.getSignatureType());
        }
    }

    @Override
    public String getVersion() {
        return version;
    }

    @Override
    public void setVersion(String version) {
        this.version = version;
    }

    @Override
    public PowerAuthHttpHeader getHttpHeader() {
        return httpHeader;
    }

    @Override
    public void setHttpHeader(PowerAuthHttpHeader httpHeader) {
        this.httpHeader = httpHeader;
    }

    @Override
    public PowerAuthActivation getActivationContext() {
        return activationContext;
    }

    @Override
    public void setActivationContext(PowerAuthActivation activationContext) {
        this.activationContext = activationContext;
        // Update deprecated activationId and activationFlags to ensure compatibility
        if (activationContext != null) {
            setActivationId(activationContext.getActivationId());
            setActivationFlags(activationContext.getActivationFlags());
        }
    }

}
