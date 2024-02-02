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

import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request object for activation layer 2 request.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@Data
@NoArgsConstructor
public class ActivationLayer2Request {

    /**
     * Base64 encoded device public key.
     */
    private String devicePublicKey;

    /**
     * Additional activation OTP.
     */
    private String activationOtp;

    /**
     * Activation name.
     */
    private String activationName;

    /**
     * Activation extras.
     */
    private String extras;

    /**
     * User device platform.
     */
    private String platform;

    /**
     * Information about user device.
     */
    private String deviceInfo;

    /**
     * Parameterized constructor.
     * @param devicePublicKey Device public key.
     * @param activationName Activation name.
     * @param extras Activation extras.
     */
    public ActivationLayer2Request(String devicePublicKey, String activationName, String extras) {
        this.devicePublicKey = devicePublicKey;
        this.activationName = activationName;
        this.extras = extras;
    }

}