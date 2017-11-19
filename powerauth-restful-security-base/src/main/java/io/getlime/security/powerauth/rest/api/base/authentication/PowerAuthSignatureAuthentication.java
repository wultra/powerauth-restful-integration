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
package io.getlime.security.powerauth.rest.api.base.authentication;

/**
 * PowerAuth authentication object used between PowerAuth Client and intermediate server
 * application (such as mobile banking API).
 *
 * @author Petr Dvorak, petr@lime-company.eu
 *
 */
public interface PowerAuthSignatureAuthentication extends PowerAuthAuthentication {

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
     * Get signature.
     * @return Signature.
     */
    String getSignature();

    /**
     * Set signature.
     * @param signature Signature.
     */
    void setSignature(String signature);

    /**
     * Get signature type.
     * @return Signature type.
     */
    String getSignatureType();

    /**
     * Set signature type.
     * @param signatureType Signature type.
     */
    void setSignatureType(String signatureType);

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

}
