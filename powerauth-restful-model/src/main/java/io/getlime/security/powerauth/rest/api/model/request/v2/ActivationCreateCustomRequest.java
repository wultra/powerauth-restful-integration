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

package io.getlime.security.powerauth.rest.api.model.request.v2;

import java.util.Map;

/**
 * Request object for /pa/activation/direct/create end-point.
 *
 * Object representing an activation performed with given identity, custom (non-identity related) attributes, and
 * PowerAuth 2.0 activation object.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class ActivationCreateCustomRequest {

    private Map<String, String> identity;
    private Map<String, Object> customAttributes;
    private ActivationCreateRequest powerauth;

    public Map<String, String> getIdentity() {
        return identity;
    }

    public void setIdentity(Map<String, String> identity) {
        this.identity = identity;
    }

    public Map<String, Object> getCustomAttributes() {
        return customAttributes;
    }

    public void setCustomAttributes(Map<String, Object> customAttributes) {
        this.customAttributes = customAttributes;
    }

    public ActivationCreateRequest getPowerauth() {
        return powerauth;
    }

    public void setPowerauth(ActivationCreateRequest powerauth) {
        this.powerauth = powerauth;
    }
}
