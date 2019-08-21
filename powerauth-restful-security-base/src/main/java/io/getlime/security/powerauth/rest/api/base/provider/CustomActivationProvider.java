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
package io.getlime.security.powerauth.rest.api.base.provider;

import io.getlime.security.powerauth.rest.api.model.entity.ActivationType;

import java.util.Map;

/**
 * Interface which enables implementation of custom activations. The interface defines a method for obtaining
 * a user ID based on arbitrary identity attributes, processing of custom activation attributes and configuration
 * of auto-commit mode.
 *
 * @author Petr Dvorak, petr@wultra.com
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public interface CustomActivationProvider {

    /**
     * This method is responsible for looking user ID up based on a provided set of identity attributes.
     * <br><br>
     * This method is called for the CUSTOM activation type only.
     *
     * @param identityAttributes Attributes that uniquely identify user with given ID.
     * @return User ID value.
     */
    String lookupUserIdForAttributes(Map<String, String> identityAttributes);

    /**
     * Process custom attributes, in any way that is suitable for the purpose of your application.
     * <br><br>
     * This method is called for all activation types.
     *
     * @param customAttributes Custom attributes (not related to identity) to be processed.
     * @param activationId Activation ID of created activation.
     * @param userId User ID of user who created the activation.
     * @param activationType Activation type.
     * @return Custom attributes after processing.
     */
    Map<String, Object> processCustomActivationAttributes(Map<String, Object> customAttributes, String activationId, String userId, ActivationType activationType);

    /**
     * Variable that specifies if the activation should be automatically committed based on provided attributes.
     * Return true in case you would like to create an activation that is ready to be used for signing (ACTIVE),
     * and false for the cases when you need activation to remain in OTP_USED state.
     * <br><br>
     * Note that this setting only affects CUSTOM or RECOVERY activation types. On CODE activation type, auto-commit
     * is always disabled.
     *
     * @param identityAttributes Identity related attributes.
     * @param customAttributes Custom attributes, not related to identity.
     * @param activationId Activation ID of created activation.
     * @param userId User ID of user who created the activation.
     * @param activationType Activation type.
     * @return True in case activation should be committed, false otherwise.
     */
    boolean shouldAutoCommitActivation(Map<String, String> identityAttributes, Map<String, Object> customAttributes, String activationId, String userId, ActivationType activationType);

    /**
     * Method is called when activation commit succeeds.
     * <br><br>
     * Note that this method is only called for CUSTOM or RECOVERY activation types, and only in the case activation
     * was successfully committed on the server side. Method is not called in case commit fails on server. On CODE
     * activation type, auto-commit is always disabled and hence this method is not called.
     *
     * @param identityAttributes Identity related attributes.
     * @param customAttributes Custom attributes, not related to identity.
     * @param activationId Activation ID of created activation.
     * @param userId User ID of user who created the activation.
     * @param activationType Activation type.
     */
    void activationWasCommitted(Map<String, String> identityAttributes, Map<String, Object> customAttributes, String activationId, String userId, ActivationType activationType);

    /**
     * Get maximum failed attempt count for activations.
     * Use null value for using value which is configured on PowerAuth server.
     * <br><br>
     * Note that this method is only called for CUSTOM or RECOVERY activation types, since for CODE activation,
     * the number of max. failed attempts is set earlier while creating the activation code.
     *
     * @param identityAttributes Identity related attributes.
     * @param customAttributes Custom attributes, not related to identity.
     * @param userId User ID of user who created the activation.
     * @param activationType Activation type.
     * @return Maximum failed attempt count for activations.
     */
    Integer getMaxFailedAttemptCount(Map<String, String> identityAttributes, Map<String, Object> customAttributes, String userId, ActivationType activationType);

    /**
     * Get length of the period of activation record validity during activation in milliseconds.
     * Use null value for using value which is configured on PowerAuth server.
     * <br><br>
     * Note that this method is only called for CUSTOM or RECOVERY activation types, since for CODE activation,
     * the expiration period for activation is set earlier while creating the activation code.
     *
     * @param identityAttributes Identity related attributes.
     * @param customAttributes Custom attributes, not related to identity.
     * @param userId User ID of user who created the activation.
     * @param activationType Activation type.
     * @return Period in milliseconds during which activation is valid before it expires.
     */
    Integer getValidityPeriodDuringActivation(Map<String, String> identityAttributes, Map<String, Object> customAttributes, String userId, ActivationType activationType);

}
