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
package com.wultra.security.powerauth.rest.api.spring.authentication;

import com.wultra.security.powerauth.http.PowerAuthHttpHeader;
import com.wultra.security.powerauth.rest.api.spring.model.ActivationStatus;

import java.util.List;

/**
 * PowerAuth authentication object used between PowerAuth Client and intermediate server
 * application (such as mobile banking API). Used in version 4 of the protocol.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public interface PowerAuthCodeAuthentication extends PowerAuthAuthentication {

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
     * Get application key.
     * @return Application key.
     */
    String getApplicationKey();

    /**
     * Set application key.
     * @param applicationKey Application key.
     */
    void setApplicationKey(String applicationKey);

    /**
     * Get authentication code.
     * @return Authentication code.
     */
    String getAuthenticationCode();

    /**
     * Set authentication code.
     * @param authenticationCode Authentication code.
     */
    void setAuthenticationCode(String authenticationCode);

    /**
     * Get authentication code type.
     * @return Authentication code type.
     */
    String getAuthenticationCodeType();

    /**
     * Set authentication code type.
     * @param authenticationCodeType Authentication code type.
     */
    void setAuthenticationCodeType(String authenticationCodeType);

    /**
     * Get request URI identifier.
     * @return Request URI identifier.
     */
    String getRequestUri();

    /**
     * Set request URI identifier.
     * @param requestUri Request URI identifier.
     */
    void setRequestUri(String requestUri);

    /**
     * Get HTTP method.
     * @return HTTP method.
     */
    String getHttpMethod();

    /**
     * Set HTTP method.
     * @param httpMethod HTTP method.
     */
    void setHttpMethod(String httpMethod);

    /**
     * Get nonce.
     * @return Nonce.
     */
    byte[] getNonce();

    /**
     * Set nonce.
     * @param nonce Nonce.
     */
    void setNonce(byte[] nonce);

    /**
     * Get request data.
     * @return Request data.
     */
    byte[] getData();

    /**
     * Set request data.
     * @param data Request data.
     */
    void setData(byte[] data);

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
     * Get activation states for which authentication is allowed.
     * @return Allowed activation states.
     */
    List<ActivationStatus> getAllowedStates();

    /**
     * Set activation states for which authentication is allowed.
     * @param allowedStates Allowed activation states.
     */
    void setAllowedStates(List<ActivationStatus> allowedStates);

    /**
     * Get parsed PowerAuth HTTP header.
     * @return PowerAuth HTTP header.
     */
    PowerAuthHttpHeader getHttpHeader();

    /**
     * Set parsed PowerAuth HTTP header.
     * @param httpHeader PowerAuth HTTP header.
     */
    void setHttpHeader(PowerAuthHttpHeader httpHeader);

}
