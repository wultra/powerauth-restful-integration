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
package io.getlime.security.powerauth.rest.api.jaxrs.service.v3;

import io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub;
import io.getlime.security.powerauth.rest.api.base.application.PowerAuthApplicationConfiguration;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.encryption.PowerAuthEciesEncryption;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthActivationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthRecoveryException;
import io.getlime.security.powerauth.rest.api.base.provider.CustomActivationProvider;
import io.getlime.security.powerauth.rest.api.model.entity.ActivationType;
import io.getlime.security.powerauth.rest.api.model.request.v3.ActivationLayer1Request;
import io.getlime.security.powerauth.rest.api.model.request.v3.ActivationStatusRequest;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationLayer1Response;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationRemoveResponse;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationStatusResponse;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import io.getlime.security.powerauth.soap.axis.client.PowerAuthServiceClient;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.soap.SOAPFaultDetail;
import org.apache.axis2.AxisFault;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ejb.Stateless;
import javax.inject.Inject;
import java.util.*;

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
@Stateless(name = "ActivationServiceV3")
public class ActivationService {

    @Inject
    private PowerAuthServiceClient powerAuthClient;

    @Inject
    private PowerAuthApplicationConfiguration applicationConfiguration;

    @Inject
    private CustomActivationProvider activationProvider;

    private static final Logger logger = LoggerFactory.getLogger(ActivationService.class);

    /**
     * Create activation.
     *
     * @param request Create activation layer 1 request.
     * @param eciesEncryption PowerAuth ECIES encryption object.
     * @return Create activation layer 1 response.
     * @throws PowerAuthActivationException In case create activation fails.
     * @throws PowerAuthRecoveryException In case activation recovery fails.
     */
    public ActivationLayer1Response createActivation(ActivationLayer1Request request, PowerAuthEciesEncryption eciesEncryption) throws PowerAuthActivationException, PowerAuthRecoveryException {
        try {

            final String applicationKey = eciesEncryption.getContext().getApplicationKey();
            final EciesEncryptedRequest activationData = request.getActivationData();
            final String ephemeralPublicKey = activationData.getEphemeralPublicKey();
            final String encryptedData = activationData.getEncryptedData();
            final String mac = activationData.getMac();
            final String nonce = activationData.getNonce();
            final Map<String, Object> customAttributes = request.getCustomAttributes();
            final Map<String, String> identity = request.getIdentityAttributes();

            // Validate inner encryption
            if (nonce == null && !"3.0".equals(eciesEncryption.getContext().getVersion())) {
                throw new PowerAuthActivationException();
            }

            switch (request.getType()) {
                // Regular activation which uses "code" identity attribute
                case CODE: {
                    // Extract data from request and encryption object
                    String activationCode = request.getIdentityAttributes().get("code");

                    // Call PrepareActivation SOAP method on PA server
                    PowerAuthPortV3ServiceStub.PrepareActivationResponse response = powerAuthClient.prepareActivation(activationCode, applicationKey, ephemeralPublicKey, encryptedData, mac, nonce);

                    Map<String, Object> processedCustomAttributes = customAttributes;
                    // In case a custom activation provider is enabled, process custom attributes and save any flags
                    if (activationProvider != null) {
                        processedCustomAttributes = activationProvider.processCustomActivationAttributes(customAttributes, response.getActivationId(), response.getUserId(), response.getApplicationId(), ActivationType.CODE);
                        List<String> activationFlags = activationProvider.getActivationFlags(identity, processedCustomAttributes, response.getActivationId(), response.getUserId(), response.getApplicationId(), ActivationType.CODE);
                        if (activationFlags != null && !activationFlags.isEmpty()) {
                            powerAuthClient.createActivationFlags(response.getActivationId(), activationFlags);
                        }
                    }

                    boolean notifyActivationCommit = false;
                    if (response.getActivationStatus() == PowerAuthPortV3ServiceStub.ActivationStatus.ACTIVE) {
                        // Activation was committed instantly due to presence of Activation OTP.
                        notifyActivationCommit = true;
                    } else {
                        // Otherwise check if activation should be committed instantly and if yes, perform commit.
                        if (activationProvider != null && activationProvider.shouldAutoCommitActivation(identity, customAttributes, response.getActivationId(), response.getUserId(), response.getApplicationId(), ActivationType.CODE)) {
                            PowerAuthPortV3ServiceStub.CommitActivationResponse commitResponse = powerAuthClient.commitActivation(response.getActivationId(), null);
                            notifyActivationCommit = commitResponse.getActivated();
                        }
                    }
                    // Notify activation provider about an activation commit.
                    if (activationProvider != null && notifyActivationCommit) {
                        activationProvider.activationWasCommitted(identity, customAttributes, response.getActivationId(), response.getUserId(), response.getApplicationId(), ActivationType.CODE);
                    }

                    // Prepare and return encrypted response
                    return prepareEncryptedResponse(response.getEncryptedData(), response.getMac(), processedCustomAttributes);
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
                    final Integer maxFailed = activationProvider.getMaxFailedAttemptCount(identity, customAttributes, userId, ActivationType.CUSTOM);
                    final Long maxFailedCount = maxFailed == null ? null : maxFailed.longValue();
                    final Integer activationValidityPeriod = activationProvider.getValidityPeriodDuringActivation(identity, customAttributes, userId, ActivationType.CUSTOM);
                    Date activationExpireTimestamp = null;
                    if (activationValidityPeriod != null) {
                        Calendar activationExpiration = GregorianCalendar.getInstance();
                        activationExpiration.add(Calendar.MILLISECOND, activationValidityPeriod);
                        activationExpireTimestamp = activationExpiration.getTime();
                    }

                    // Create activation for a looked up user and application related to the given application key
                    PowerAuthPortV3ServiceStub.CreateActivationResponse response = powerAuthClient.createActivation(
                            userId,
                            activationExpireTimestamp,
                            maxFailedCount,
                            applicationKey,
                            ephemeralPublicKey,
                            encryptedData,
                            mac,
                            nonce
                    );

                    // Process custom attributes using a custom logic
                    final Map<String, Object> processedCustomAttributes = activationProvider.processCustomActivationAttributes(customAttributes, response.getActivationId(), userId, response.getApplicationId(), ActivationType.CUSTOM);

                    // Save activation flags in case the provider specified any flags
                    List<String> activationFlags = activationProvider.getActivationFlags(identity, processedCustomAttributes, response.getActivationId(), userId, response.getApplicationId(), ActivationType.CUSTOM);
                    if (activationFlags != null && !activationFlags.isEmpty()) {
                        powerAuthClient.createActivationFlags(response.getActivationId(), activationFlags);
                    }

                    // Check if activation should be committed instantly and if yes, perform commit
                    if (activationProvider.shouldAutoCommitActivation(identity, customAttributes, response.getActivationId(), userId, response.getApplicationId(), ActivationType.CUSTOM)) {
                        PowerAuthPortV3ServiceStub.CommitActivationResponse commitResponse = powerAuthClient.commitActivation(response.getActivationId(), null);
                        if (commitResponse.getActivated()) {
                            activationProvider.activationWasCommitted(identity, customAttributes, response.getActivationId(), userId, response.getApplicationId(), ActivationType.CUSTOM);
                        }
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

                // Activation using recovery code
                case RECOVERY: {

                    if (request.getIdentityAttributes() == null) {
                        throw new PowerAuthActivationException();
                    }

                    // Extract data from request and encryption object
                    String recoveryCode = request.getIdentityAttributes().get("recoveryCode");
                    String recoveryPuk = request.getIdentityAttributes().get("puk");

                    if (recoveryCode == null || recoveryCode.isEmpty()) {
                        throw new PowerAuthActivationException();
                    }

                    if (recoveryPuk == null || recoveryPuk.isEmpty()) {
                        throw new PowerAuthActivationException();
                    }

                    // Resolve maxFailedCount, user ID is not known
                    Long maxFailedCount = null;
                    if (activationProvider != null) {
                        final Integer maxFailed = activationProvider.getMaxFailedAttemptCount(identity, customAttributes, null, ActivationType.RECOVERY);
                        maxFailedCount = maxFailed == null ? null : maxFailed.longValue();
                    }

                    // Call RecoveryCodeActivation SOAP method on PA server
                    PowerAuthPortV3ServiceStub.RecoveryCodeActivationResponse response = powerAuthClient.createActivationUsingRecoveryCode(recoveryCode, recoveryPuk, applicationKey, maxFailedCount, ephemeralPublicKey, encryptedData, mac, nonce);

                    Map<String, Object> processedCustomAttributes = customAttributes;
                    // In case a custom activation provider is enabled, process custom attributes and save any flags
                    if (activationProvider != null) {
                        processedCustomAttributes = activationProvider.processCustomActivationAttributes(customAttributes, response.getActivationId(), response.getUserId(), response.getApplicationId(), ActivationType.RECOVERY);
                        List<String> activationFlags = activationProvider.getActivationFlags(identity, processedCustomAttributes, response.getActivationId(), response.getUserId(), response.getApplicationId(), ActivationType.RECOVERY);
                        if (activationFlags != null && !activationFlags.isEmpty()) {
                            powerAuthClient.createActivationFlags(response.getActivationId(), activationFlags);
                        }
                    }

                    // Automatically commit activation by default, the optional activation provider can override automatic commit
                    if (activationProvider == null || activationProvider.shouldAutoCommitActivation(identity, customAttributes, response.getActivationId(), response.getUserId(), response.getApplicationId(), ActivationType.RECOVERY)) {
                        PowerAuthPortV3ServiceStub.CommitActivationResponse commitResponse = powerAuthClient.commitActivation(response.getActivationId(), null);
                        if (activationProvider != null && commitResponse.getActivated()) {
                            activationProvider.activationWasCommitted(identity, customAttributes, response.getActivationId(), response.getUserId(), response.getApplicationId(), ActivationType.RECOVERY);
                        }
                    }

                    // Prepare and return encrypted response
                    return prepareEncryptedResponse(response.getEncryptedData(), response.getMac(), processedCustomAttributes);
                }

                default:
                    throw new PowerAuthAuthenticationException("Unsupported activation type: " + request.getType());
            }
        } catch (AxisFault ex) {
            if (ex.getFaultDetailElement() != null) {
                handleInvalidRecoveryError(ex.getFaultDetailElement());
            }
            logger.warn("Creating PowerAuth activation failed", ex);
            throw new PowerAuthActivationException();
        } catch (PowerAuthActivationException ex) {
            // Do not swallow PowerAuthActivationException for custom activations.
            // See: https://github.com/wultra/powerauth-restful-integration/issues/199
            logger.warn("Creating PowerAuth activation failed", ex);
            throw ex;
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
            String challenge = request.getChallenge();
            PowerAuthPortV3ServiceStub.GetActivationStatusResponse soapResponse = powerAuthClient.getActivationStatusWithEncryptedStatusBlob(activationId, challenge);
            ActivationStatusResponse response = new ActivationStatusResponse();
            response.setActivationId(soapResponse.getActivationId());
            response.setEncryptedStatusBlob(soapResponse.getEncryptedStatusBlob());
            response.setNonce(soapResponse.getEncryptedStatusBlobNonce());
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

            // Fetch context information
            final String activationId = apiAuthentication.getActivationId();
            final String userId = apiAuthentication.getUserId();
            final Long applicationId = apiAuthentication.getApplicationId();

            // Call other application specific cleanup logic
            final PowerAuthPortV3ServiceStub.RemoveActivationResponse soapResponse;
            if (activationProvider != null) {
                final boolean revokeCodes = activationProvider.shouldRevokeRecoveryCodeOnRemove(activationId, userId, applicationId);
                soapResponse = powerAuthClient.removeActivation(activationId, null, revokeCodes);
                activationProvider.activationWasRemoved(activationId, userId, applicationId);
            } else {
                soapResponse = powerAuthClient.removeActivation(activationId, null); // do not revoke recovery codes
            }

            // Prepare and return the response
            ActivationRemoveResponse response = new ActivationRemoveResponse();
            response.setActivationId(soapResponse.getActivationId());
            return response;
        } catch (Exception ex) {
            logger.warn("PowerAuth activation removal failed", ex);
            throw new PowerAuthActivationException();
        }
    }

    /**
     * Handle SOAP fault for recovery error which may contain additional details about current recovery PUK index.
     * @param faultDetail SOAP fault detail.
     * @throws PowerAuthRecoveryException Thrown in case recovery error is handled using this method.
     */
    private void handleInvalidRecoveryError(SOAPFaultDetail faultDetail) throws PowerAuthRecoveryException {
        String errorCode = null;
        String errorMessage = null;
        Integer currentRecoveryPukIndex = null;
        Iterator iter = faultDetail.getAllDetailEntries();
        while (iter.hasNext()) {
            OMElement node = (OMElement) iter.next();
            switch (node.getLocalName()) {
                case "errorCode":
                    errorCode = node.getText();
                    break;
                case "localizedMessage":
                    errorMessage = node.getText();
                    break;
                case "currentRecoveryPukIndex":
                    try {
                        currentRecoveryPukIndex = Integer.parseInt(node.getText());
                    } catch (NumberFormatException ex) {
                        // Ignore invalid index
                    }
                    break;
            }
        }
        if ("ERR0028".equals(errorCode)) {
            throw new PowerAuthRecoveryException(errorMessage, "INVALID_RECOVERY_CODE", currentRecoveryPukIndex);
        }
    }

    /**
     * Prepare payload for the encrypted response.
     *
     * @param encryptedData Encrypted data.
     * @param mac MAC code of the encrypted data.
     * @param processedCustomAttributes Custom attributes to be returned.
     * @return Encrypted response object.
     */
    private ActivationLayer1Response prepareEncryptedResponse(String encryptedData, String mac, Map<String, Object> processedCustomAttributes) {
        // Prepare encrypted response object for layer 2
        EciesEncryptedResponse encryptedResponseL2 = new EciesEncryptedResponse();
        encryptedResponseL2.setEncryptedData(encryptedData);
        encryptedResponseL2.setMac(mac);

        // The response is encrypted once more before sent to client using ResponseBodyAdvice
        ActivationLayer1Response responseL1 = new ActivationLayer1Response();
        responseL1.setCustomAttributes(processedCustomAttributes);
        responseL1.setActivationData(encryptedResponseL2);
        return responseL1;
    }

}
