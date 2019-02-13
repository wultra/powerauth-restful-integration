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
package io.getlime.security.powerauth.rest.api.spring.service.v3;

import io.getlime.powerauth.soap.v3.CreateActivationResponse;
import io.getlime.powerauth.soap.v3.GetActivationStatusResponse;
import io.getlime.powerauth.soap.v3.PrepareActivationResponse;
import io.getlime.powerauth.soap.v3.RemoveActivationResponse;
import io.getlime.security.powerauth.rest.api.base.application.PowerAuthApplicationConfiguration;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.encryption.EciesEncryptionContext;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthActivationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.base.provider.CustomActivationProvider;
import io.getlime.security.powerauth.rest.api.model.entity.ActivationType;
import io.getlime.security.powerauth.rest.api.model.request.v3.ActivationLayer1Request;
import io.getlime.security.powerauth.rest.api.model.request.v3.ActivationStatusRequest;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationLayer1Response;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationRemoveResponse;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationStatusResponse;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import io.getlime.security.powerauth.soap.spring.client.PowerAuthServiceClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Map;

/**
 * Service implementing activation functionality.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Service("ActivationServiceV3")
public class ActivationService {

    private PowerAuthServiceClient powerAuthClient;

    private PowerAuthApplicationConfiguration applicationConfiguration;

    private CustomActivationProvider activationProvider;

    private static final Logger logger = LoggerFactory.getLogger(ActivationService.class);

    @Autowired
    public void setPowerAuthClient(PowerAuthServiceClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @Autowired(required = false)
    public void setApplicationConfiguration(PowerAuthApplicationConfiguration applicationConfiguration) {
        this.applicationConfiguration = applicationConfiguration;
    }

    @Autowired(required = false)
    public void setPowerAuthActivationProvider(CustomActivationProvider activationProvider) {
        this.activationProvider = activationProvider;
    }

    /**
     * Create activation.
     *
     * @param request Create activation layer 1 request.
     * @param eciesContext PowerAuth ECIES encryption context.
     * @return Create activation layer 1 response.
     * @throws PowerAuthActivationException In case create activation fails.
     */
    public ActivationLayer1Response createActivation(ActivationLayer1Request request, EciesEncryptionContext eciesContext) throws PowerAuthActivationException {
        try {

            final String applicationKey = eciesContext.getApplicationKey();
            final EciesEncryptedRequest activationData = request.getActivationData();
            final String ephemeralPublicKey = activationData.getEphemeralPublicKey();
            final String encryptedData = activationData.getEncryptedData();
            final String mac = activationData.getMac();
            final Map<String, Object> customAttributes = request.getCustomAttributes();
            final Map<String, String> identity = request.getIdentityAttributes();

            switch (request.getType()) {
                // Regular activation which uses "code" identity attribute
                case CODE: {
                    // Extract data from request and encryption object
                    String activationCode = request.getIdentityAttributes().get("code");

                    // Call PrepareActivation SOAP method on PA server
                    PrepareActivationResponse response = powerAuthClient.prepareActivation(activationCode, applicationKey, ephemeralPublicKey, encryptedData, mac);

                    Map<String, Object> processedCustomAttributes = customAttributes;
                    // In case a custom activation provider is enabled, process custom attributes
                    if (activationProvider != null) {
                        processedCustomAttributes = activationProvider.processCustomActivationAttributes(customAttributes, response.getActivationId(), response.getUserId(), ActivationType.CODE);
                    }

                    // Prepare encrypted response object for layer 2
                    EciesEncryptedResponse encryptedResponseL2 = new EciesEncryptedResponse();
                    encryptedResponseL2.setEncryptedData(response.getEncryptedData());
                    encryptedResponseL2.setMac(response.getMac());

                    // The response is encrypted once more before sent to client using ResponseBodyAdvice
                    ActivationLayer1Response responseL1 = new ActivationLayer1Response();
                    responseL1.setCustomAttributes(processedCustomAttributes);
                    responseL1.setActivationData(encryptedResponseL2);
                    return responseL1;
                }

                // Custom activation
                case CUSTOM: {
                    // Check if there is a custom activation provider available, return an error in case it is not available
                    if (activationProvider == null) {
                        throw new PowerAuthActivationException();
                    }

                    // Lookup user ID using a provided identity attributes
                    String userId = activationProvider.lookupUserIdForAttributes(identity);

                    // If no user was found or user ID is invalid, return an error
                    if (userId == null || userId.equals("") || userId.length() > 255) {
                        throw new PowerAuthActivationException();
                    }

                    // Resolve maxFailedCount and activationExpireTimestamp parameters, null value means use value configured on PowerAuth server
                    Integer maxFailed = activationProvider.getMaxFailedAttemptCount(identity, customAttributes, userId);
                    final Long maxFailedCount = maxFailed == null ? null : maxFailed.longValue();
                    final Integer activationValidityPeriod = activationProvider.getValidityPeriodDuringActivation(identity, customAttributes, userId);
                    Date activationExpireTimestamp = null;
                    if (activationValidityPeriod != null) {
                        Calendar activationExpiration = GregorianCalendar.getInstance();
                        activationExpiration.add(Calendar.MILLISECOND, activationValidityPeriod);
                        activationExpireTimestamp = activationExpiration.getTime();
                    }

                    // Create activation for a looked up user and application related to the given application key
                    CreateActivationResponse response = powerAuthClient.createActivation(
                            userId,
                            activationExpireTimestamp,
                            maxFailedCount,
                            applicationKey,
                            ephemeralPublicKey,
                            encryptedData,
                            mac
                    );

                    // Process custom attributes using a custom logic
                    final Map<String, Object> processedCustomAttributes = activationProvider.processCustomActivationAttributes(customAttributes, response.getActivationId(), userId, ActivationType.CUSTOM);

                    // Check if activation should be committed instantly and if yes, perform commit
                    if (activationProvider.shouldAutoCommitActivation(identity, customAttributes, response.getActivationId(), userId)) {
                        powerAuthClient.commitActivation(response.getActivationId());
                    }

                    // Prepare encrypted activation data
                    EciesEncryptedResponse encryptedActivationData = new EciesEncryptedResponse(response.getEncryptedData(), response.getMac());

                    // Prepare the created activation response data
                    ActivationLayer1Response responseL1 = new ActivationLayer1Response();
                    responseL1.setCustomAttributes(processedCustomAttributes);
                    responseL1.setActivationData(encryptedActivationData);

                    // Return response
                    return responseL1;
                }

                default:
                    throw new PowerAuthAuthenticationException("Unsupported activation type: " + request.getType());
            }
        } catch (Exception ex) {
            logger.warn("Creating PowerAuth activation failed", ex);
            throw new PowerAuthActivationException();
        }
    }

    /**
     * Get activation status.
     *
     * @param request Activation status request.
     * @return Activation status response.
     * @throws PowerAuthActivationException In case retrieving activation status fails.
     */
    public ActivationStatusResponse getActivationStatus(ActivationStatusRequest request) throws PowerAuthActivationException {
        try {
            String activationId = request.getActivationId();
            GetActivationStatusResponse soapResponse = powerAuthClient.getActivationStatus(activationId);
            ActivationStatusResponse response = new ActivationStatusResponse();
            response.setActivationId(soapResponse.getActivationId());
            response.setEncryptedStatusBlob(soapResponse.getEncryptedStatusBlob());
            if (applicationConfiguration != null) {
                response.setCustomObject(applicationConfiguration.statusServiceCustomObject());
            }
            return response;
        } catch (Exception ex) {
            logger.warn("PowerAuth activation status check failed", ex);
            throw new PowerAuthActivationException();
        }
    }

    /**
     * Remove activation.
     *
     * @param apiAuthentication PowerAuth API authentication object.
     * @return Activation remove response.
     * @throws PowerAuthActivationException     In case remove activation fails.
     */
    public ActivationRemoveResponse removeActivation(PowerAuthApiAuthentication apiAuthentication) throws PowerAuthActivationException {
        try {
            RemoveActivationResponse soapResponse = powerAuthClient.removeActivation(apiAuthentication.getActivationId());
            ActivationRemoveResponse response = new ActivationRemoveResponse();
            response.setActivationId(soapResponse.getActivationId());
            return response;
        } catch (Exception ex) {
            logger.warn("PowerAuth activation removal failed", ex);
            throw new PowerAuthActivationException();
        }
    }
}
