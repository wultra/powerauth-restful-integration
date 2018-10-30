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
package io.getlime.security.powerauth.rest.api.model.response.v3;

import java.util.Map;

/**
 * Response object for /pa/v3/activation/status end-point.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public class ActivationStatusResponse {

    private String activationId;
    private String encryptedStatusBlob;
    private Map<String, Object> customObject;

    /**
     * Get activation ID
     * @return Activation ID
     */
    public String getActivationId() {
        return activationId;
    }

    /**
     * Set activation ID
     * @param activationId Activation ID
     */
    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    /**
     * Get encrypted activation status blob
     * @return Encrypted activation status blob
     */
    public String getEncryptedStatusBlob() {
        return encryptedStatusBlob;
    }

    /**
     * Set encrypted activation status blob
     * @param cStatusBlob encrypted activation status blob
     */
    public void setEncryptedStatusBlob(String cStatusBlob) {
        this.encryptedStatusBlob = cStatusBlob;
    }

    /**
     * Get custom associated object.
     * @return Custom associated object
     */
    public Map<String, Object> getCustomObject() {
        return customObject;
    }

    /**
     * Set custom associated object
     * @param customObject Custom associated object
     */
    public void setCustomObject(Map<String, Object> customObject) {
        this.customObject = customObject;
    }

}
