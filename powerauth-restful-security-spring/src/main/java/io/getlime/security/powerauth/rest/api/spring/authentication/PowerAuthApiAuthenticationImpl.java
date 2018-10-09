/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2017 Lime - HighTech Solutions s.r.o.
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

import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.http.PowerAuthHttpHeader;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

/**
 * PowerAuth API authentication object used between intermediate server application (such as mobile 
 * banking API) and core systems (such as banking core).
 *
 * @author Petr Dvorak, petr@lime-company.eu
 *
 */
public class PowerAuthApiAuthenticationImpl extends AbstractAuthenticationToken implements PowerAuthApiAuthentication, Serializable {

    private static final long serialVersionUID = -3790516505615465445L;

    private String activationId;
    private String userId;
    private Long applicationId;
    private PowerAuthSignatureTypes factors;
    private String version;
    private PowerAuthHttpHeader httpHeader;

    /**
     * Default constructor
     */
    public PowerAuthApiAuthenticationImpl() {
        super(null);
    }

    /**
     * Constructor for a new PowerAuthApiAuthenticationImpl
     * @param activationId Activation ID
     * @param userId User ID
     * @param applicationId Application ID
     * @param factors Authentication factors
     */
    public PowerAuthApiAuthenticationImpl(String activationId, String userId, Long applicationId, PowerAuthSignatureTypes factors) {
        super(null);
        this.activationId = activationId;
        this.userId = userId;
        this.applicationId = applicationId;
        this.factors = factors;
    }

    @Override
    public String getName() {
        return userId;
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        ArrayList<GrantedAuthority> authorities = new ArrayList<>(1);
        authorities.add(new SimpleGrantedAuthority("USER"));
        return Collections.unmodifiableList(authorities);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return this.activationId;
    }

    /**
     * Get user ID
     * @return User ID
     */
    @Override
    public String getUserId() {
        return userId;
    }

    /**
     * Set user ID
     * @param userId User ID
     */
    @Override
    public void setUserId(String userId) {
        this.userId = userId;
    }

    /**
     * Get activation ID
     * @return Activation ID
     */
    @Override
    public String getActivationId() {
        return activationId;
    }

    /**
     * Set activation ID
     * @param activationId Activation ID
     */
    @Override
    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    /**
     * Get application ID.
     * @return Application ID.
     */
    @Override
    public Long getApplicationId() {
        return applicationId;
    }

    /**
     * Set application ID.
     * @param id Application ID.
     */
    @Override
    public void setApplicationId(Long id) {
        this.applicationId = id;
    }

    /**
     * Get authentication factors.
     * @return Authentication factors.
     */
    @Override
    public PowerAuthSignatureTypes getSignatureFactors() {
        return factors;
    }

    /**
     * Set authentication factors.
     * @param factors Signature type (signature factors).
     */
    @Override
    public void setSignatureFactors(PowerAuthSignatureTypes factors) {
        this.factors = factors;
    }

    /**
     * Get PowerAuth protocol version.
     * @return PowerAuth protocol version.
     */
    @Override
    public String getVersion() {
        return version;
    }

    /**
     * Set PowerAuth protocol version.
     * @param version PowerAuth protocol version.
     */
    @Override
    public void setVersion(String version) {
        this.version = version;
    }

    /**
     * Get parsed PowerAuth HTTP header.
     * @return PowerAuth HTTP header.
     */
    @Override
    public PowerAuthHttpHeader getHttpHeader() {
        return httpHeader;
    }

    /**
     * Set parsed PowerAuth HTTP header.
     * @param httpHeader PowerAuth HTTP header.
     */
    @Override
    public void setHttpHeader(PowerAuthHttpHeader httpHeader) {
        this.httpHeader = httpHeader;
    }
}
