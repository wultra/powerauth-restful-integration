/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2025 Wultra s.r.o.
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

import com.wultra.security.powerauth.http.PowerAuthHttpHeader;
import com.wultra.security.powerauth.rest.api.spring.authentication.PowerAuthCodeAuthentication;
import com.wultra.security.powerauth.rest.api.spring.model.ActivationStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;

import java.io.Serial;
import java.util.List;

/**
 * PowerAuth authentication object used between PowerAuth Client and intermediate server
 * application (such as mobile banking API). Used in version 4 of the protocol.
 *
 * @author Petr Dvorak, petr@wultra.com
 *
 */
public class PowerAuthCodeAuthenticationImpl extends AbstractAuthenticationToken implements PowerAuthCodeAuthentication {

    @Serial
    private static final long serialVersionUID = 6495166873663643144L;

    /**
     * Activation ID.
     */
    private String activationId;

    /**
     * Application key.
     */
    private String applicationKey;

    /**
     * Authentication code value.
     */
    private String authenticationCode;

    /**
     * Authentication code type.
     */
    private String authenticationCodeType;

    /**
     * Request URI identifier.
     */
    private String requestUri;

    /**
     * Used HTTP method.
     */
    private String httpMethod;

    /**
     * Cryptographic nonce.
     */
    private byte[] nonce;

    /**
     * Signed data.
     */
    private byte[] data;

    /**
     * Protocol version.
     */
    private String version;

    /**
     * List of activation statuses for which authentication is allowed.
     */
    private List<ActivationStatus> allowedStates;

    /**
     * Reference to the original HTTP header.
     */
    private PowerAuthHttpHeader httpHeader;

    /**
     * Default constructor.
     */
    public PowerAuthCodeAuthenticationImpl() {
        super(AuthorityUtils.NO_AUTHORITIES);
    }

    // Authentication Token Related methods

    @Override
    public Object getCredentials() {
        return authenticationCode;
    }

    @Override
    public Object getPrincipal() {
        return activationId;
    }

    // Getters and setters for fields

    /**
     * Get activation ID.
     * @return Activation ID.
     */
    public String getActivationId() {
        return activationId;
    }

    /**
     * Set activation ID.
     * @param activationId Activation ID.
     */
    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    /**
     * Get application key.
     * @return Application key.
     */
    public String getApplicationKey() {
        return applicationKey;
    }

    /**
     * Set application key.
     * @param applicationKey Application key.
     */
    public void setApplicationKey(String applicationKey) {
        this.applicationKey = applicationKey;
    }

    /**
     * Get authentication code.
     * @return Authentication code.
     */
    public String getAuthenticationCode() {
        return authenticationCode;
    }

    /**
     * Set authentication code.
     * @param authenticationCode Authentication code.
     */
    public void setAuthenticationCode(String authenticationCode) {
        this.authenticationCode = authenticationCode;
    }

    /**
     * Get authentication code type.
     * @return Authentication code type.
     */
    public String getAuthenticationCodeType() {
        return authenticationCodeType;
    }

    /**
     * Set authentication code type.
     * @param authenticationCodeType Authentication code type.
     */
    public void setAuthenticationCodeType(String authenticationCodeType) {
        this.authenticationCodeType = authenticationCodeType;
    }

    /**
     * Get request URI identifier.
     * @return Request URI identifier.
     */
    public String getRequestUri() {
        return requestUri;
    }

    /**
     * Set request URI identifier.
     * @param requestUri Request URI identifier.
     */
    public void setRequestUri(String requestUri) {
        this.requestUri = requestUri;
    }

    /**
     * Get HTTP method.
     * @return HTTP method.
     */
    public String getHttpMethod() {
        return httpMethod;
    }

    /**
     * Set HTTP method.
     * @param httpMethod HTTP method.
     */
    public void setHttpMethod(String httpMethod) {
        this.httpMethod = httpMethod;
    }

    /**
     * Get nonce.
     * @return Nonce.
     */
    public byte[] getNonce() {
        return nonce;
    }

    /**
     * Set nonce.
     * @param nonce Nonce.
     */
    public void setNonce(byte[] nonce) {
        this.nonce = nonce;
    }

    /**
     * Get request data.
     * @return Request data.
     */
    public byte[] getData() {
        return data;
    }

    /**
     * Set request data.
     * @param data Request data.
     */
    public void setData(byte[] data) {
        this.data = data;
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
     * Get activation states for which authentication is allowed.
     * @return Allowed activation states.
     */
    @Override
    public List<ActivationStatus> getAllowedStates() {
        return allowedStates;
    }

    /**
     * Set activation states for which authentication is allowed.
     * @param allowedStates Allowed activation states.
     */
    @Override
    public void setAllowedStates(List<ActivationStatus> allowedStates) {
        this.allowedStates = allowedStates;
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
