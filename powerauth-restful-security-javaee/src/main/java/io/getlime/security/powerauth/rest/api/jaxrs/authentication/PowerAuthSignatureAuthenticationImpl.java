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
package io.getlime.security.powerauth.rest.api.jaxrs.authentication;

import io.getlime.security.powerauth.http.PowerAuthHttpHeader;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthSignatureAuthentication;

/**
 * PowerAuth authentication object used between PowerAuth Client and intermediate server
 * application (such as mobile banking API).
 *
 * @author Petr Dvorak
 *
 */
public class PowerAuthSignatureAuthenticationImpl implements PowerAuthSignatureAuthentication {

    private String activationId;
    private String applicationKey;
    private String signature;
    private String signatureType;
    private String requestUri;
    private String httpMethod;
    private byte[] nonce;
    private byte[] data;
    private String version;
    private PowerAuthHttpHeader httpHeader;
    private Integer forcedSignatureVersion;

    /**
     * Get activation ID.
     * @return Activation ID.
     */
    @Override
    public String getActivationId() {
        return activationId;
    }

    /**
     * Set activation ID.
     * @param activationId Activation ID.
     */
    @Override
    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    /**
     * Get application key.
     * @return Application key.
     */
    @Override
    public String getApplicationKey() {
        return applicationKey;
    }

    /**
     * Set application key.
     * @param applicationKey Application key.
     */
    @Override
    public void setApplicationKey(String applicationKey) {
        this.applicationKey = applicationKey;
    }

    /**
     * Get signature.
     * @return Signature.
     */
    @Override
    public String getSignature() {
        return signature;
    }

    /**
     * Set signature.
     * @param signature Signature.
     */
    @Override
    public void setSignature(String signature) {
        this.signature = signature;
    }

    /**
     * Get signature type.
     * @return Signature type.
     */
    @Override
    public String getSignatureType() {
        return signatureType;
    }

    /**
     * Set signature type.
     * @param signatureType Signature type.
     */
    @Override
    public void setSignatureType(String signatureType) {
        this.signatureType = signatureType;
    }

    /**
     * Get request URI identifier.
     * @return Request URI identifier.
     */
    @Override
    public String getRequestUri() {
        return requestUri;
    }

    /**
     * Set request URI identifier.
     * @param requestUri Request URI identifier.
     */
    @Override
    public void setRequestUri(String requestUri) {
        this.requestUri = requestUri;
    }

    /**
     * Get HTTP method.
     * @return HTTP method.
     */
    @Override
    public String getHttpMethod() {
        return httpMethod;
    }

    /**
     * Set HTTP method.
     * @param httpMethod HTTP method.
     */
    @Override
    public void setHttpMethod(String httpMethod) {
        this.httpMethod = httpMethod;
    }

    /**
     * Get nonce.
     * @return Nonce.
     */
    @Override
    public byte[] getNonce() {
        return nonce;
    }

    /**
     * Set nonce.
     * @param nonce Nonce.
     */
    @Override
    public void setNonce(byte[] nonce) {
        this.nonce = nonce;
    }

    /**
     * Get request data.
     * @return Request data.
     */
    @Override
    public byte[] getData() {
        return data;
    }

    /**
     * Set request data.
     * @param data Request data.
     */
    @Override
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

    /**
     * Get forced signature version which is used during upgrade.
     * @return Forced signature version.
     */
    @Override
    public Integer getForcedSignatureVersion() {
        return forcedSignatureVersion;
    }

    /**
     * Set forced signature version which is used during upgrade.
     * @param forcedSignatureVersion Forced signature version.
     */
    @Override
    public void setForcedSignatureVersion(Integer forcedSignatureVersion) {
        this.forcedSignatureVersion = forcedSignatureVersion;
    }
}
