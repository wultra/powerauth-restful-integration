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

package io.getlime.security.powerauth.rest.api.jaxrs.encryption;

import io.getlime.security.powerauth.rest.api.base.encryption.PowerAuthEciesEncryption;

/**
 * Implementation of the {@link PowerAuthEciesEncryption} interface.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class PowerAuthEciesEncryptionImpl implements PowerAuthEciesEncryption {

    private String applicationKey;
    private String activationId;
    private String version;

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
    public void setApplicationKey(String applicationKey) {
        this.applicationKey = applicationKey;
    }

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
    public void setActivationId(String activationId) {
        this.activationId = activationId;
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
    public void setVersion(String version) {
        this.version = version;
    }
}
