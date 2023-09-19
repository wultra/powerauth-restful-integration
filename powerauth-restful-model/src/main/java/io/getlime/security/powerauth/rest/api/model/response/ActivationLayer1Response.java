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
package io.getlime.security.powerauth.rest.api.model.response;

import java.util.Map;

/**
 * Response object for activation layer 2.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class ActivationLayer1Response {

    private EciesEncryptedResponse activationData;
    private Map<String, Object> customAttributes;
    private Map<String, Object> userInfo;

    /**
     * Get encrypted activation data.
     * @return Encrypted activation data.
     */
    public EciesEncryptedResponse getActivationData() {
        return activationData;
    }

    /**
     * Set encrypted activation data.
     * @param activationData Encrypted activation data.
     */
    public void setActivationData(EciesEncryptedResponse activationData) {
        this.activationData = activationData;
    }

    /**
     * Get custom attributes for activation.
     * @return Custom attributes.
     */
    public Map<String, Object> getCustomAttributes() {
        return customAttributes;
    }

    /**
     * Set custom attributes for activation.
     * @param customAttributes Custom attributes.
     */
    public void setCustomAttributes(Map<String, Object> customAttributes) {
        this.customAttributes = customAttributes;
    }

    /**
     * Get user info as a map of claims.
     * @return User info.
     */
    public Map<String, Object> getUserInfo() {
        return userInfo;
    }

    /**
     * Set user info via a map of claims.
     * @param userInfo User info.
     */
    public void setUserInfo(Map<String, Object> userInfo) {
        this.userInfo = userInfo;
    }
}
