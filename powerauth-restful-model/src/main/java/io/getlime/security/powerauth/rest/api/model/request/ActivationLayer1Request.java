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
package io.getlime.security.powerauth.rest.api.model.request;

import io.getlime.security.powerauth.rest.api.model.entity.ActivationType;

import java.util.Map;

/**
 * Request object for activation layer 1.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class ActivationLayer1Request {

    private ActivationType type;
    private Map<String, String> identityAttributes;
    private Map<String, Object> customAttributes;
    private EciesEncryptedRequest activationData;

    /**
     * Get activation type.
     * @return Activation type.
     */
    public ActivationType getType() {
        return type;
    }

    /**
     * Set activation type.
     * @param type Activation type.
     */
    public void setType(ActivationType type) {
        this.type = type;
    }

    /**
     * Get identity attributes.
     * @return Identity attributes.
     */
    public Map<String, String> getIdentityAttributes() {
        return identityAttributes;
    }

    /**
     * Set identity attributes.
     * @param identityAttributes Identity attributes.
     */
    public void setIdentityAttributes(Map<String, String> identityAttributes) {
        this.identityAttributes = identityAttributes;
    }

    /**
     * Get custom attributes.
     * @return Custom attributes.
     */
    public Map<String, Object> getCustomAttributes() {
        return customAttributes;
    }

    /**
     * Set custom attributes.
     * @param customAttributes Custom attributes.
     */
    public void setCustomAttributes(Map<String, Object> customAttributes) {
        this.customAttributes = customAttributes;
    }

    /**
     * Get encrypted activation data.
     * @return Encrypted activation data.
     */
    public EciesEncryptedRequest getActivationData() {
        return activationData;
    }

    /**
     * Set encrypted activation data.
     * @param activationData Encrypted activation data.
     */
    public void setActivationData(EciesEncryptedRequest activationData) {
        this.activationData = activationData;
    }
}
