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
package io.getlime.security.powerauth.app.rest.api.javaee.provider;

import java.util.Map;

/**
 * Interface that specifies a method for obtaining a user ID based on arbitrary attributes.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public interface PowerAuthUserProvider {

    /**
     * This method is responsible for looking user ID up based on a provided set of identity attributes.
     * @param identityAttributes Attributes that uniquely identify user with given ID.
     * @return User ID value.
     */
    String lookupUserIdForAttributes(Map<String, String> identityAttributes);

    /**
     * Variable that specifies if the activation should be automatically commited based on provided attributes.
     * Return true in case you would like to create an activation that is ready to be used for signing (ACTIVE),
     * and false for the cases when you need activation to remain in OTP_USED state.
     *
     * @param identityAttributes Identity related attributes.
     * @param customAttributes Custom attributes, not related to identity.
     * @return True in case activation should be commited, false otherwise.
     */
    boolean shouldAutoCommitActivation(Map<String, String> identityAttributes, Map<String, Object> customAttributes);

    /**
     * Process custom attributes, in any way that is suitable for the purpose of your application.
     * @param customAttributes Custom attributes (not related to identity) to be processed.
     */
    void processCustomActivationAttributes(Map<String, Object> customAttributes);

}
