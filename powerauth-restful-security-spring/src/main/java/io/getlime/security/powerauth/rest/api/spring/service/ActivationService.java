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
package io.getlime.security.powerauth.rest.api.spring.service;

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.enumeration.ActivationStatus;
import com.wultra.security.powerauth.client.model.error.PowerAuthClientException;
import com.wultra.security.powerauth.client.model.error.PowerAuthErrorRecovery;
import com.wultra.security.powerauth.client.model.request.*;
import com.wultra.security.powerauth.client.model.response.*;
import io.getlime.security.powerauth.rest.api.model.entity.ActivationType;
import io.getlime.security.powerauth.rest.api.model.entity.UserInfoStage;
import io.getlime.security.powerauth.rest.api.model.request.ActivationLayer1Request;
import io.getlime.security.powerauth.rest.api.model.request.ActivationStatusRequest;
import io.getlime.security.powerauth.rest.api.model.request.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.ActivationLayer1Response;
import io.getlime.security.powerauth.rest.api.model.response.ActivationRemoveResponse;
import io.getlime.security.powerauth.rest.api.model.response.ActivationStatusResponse;
import io.getlime.security.powerauth.rest.api.model.response.EciesEncryptedResponse;
import io.getlime.security.powerauth.rest.api.spring.application.PowerAuthApplicationConfiguration;
import io.getlime.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.spring.converter.ActivationContextConverter;
import io.getlime.security.powerauth.rest.api.spring.encryption.EciesEncryptionContext;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthActivationException;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthRecoveryException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import io.getlime.security.powerauth.rest.api.spring.model.ActivationContext;
import io.getlime.security.powerauth.rest.api.spring.model.UserInfoContext;
import io.getlime.security.powerauth.rest.api.spring.provider.CustomActivationProvider;
import io.getlime.security.powerauth.rest.api.spring.provider.UserInfoProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
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
@Service("activationServiceV3")
public class ActivationService {

    private static final Logger logger = LoggerFactory.getLogger(ActivationService.class);

    private final PowerAuthClient powerAuthClient;
    private final HttpCustomizationService httpCustomizationService;
    private final ActivationContextConverter activationContextConverter;

    private PowerAuthApplicationConfiguration applicationConfiguration;
    private CustomActivationProvider activationProvider;
    private UserInfoProvider userInfoProvider;


    /**
     * Service constructor.
     * @param powerAuthClient PowerAuth client.
     * @param httpCustomizationService HTTP customization service.
     * @param activationContextConverter Activation context converter.
     */
    @Autowired
    public ActivationService(PowerAuthClient powerAuthClient, HttpCustomizationService httpCustomizationService, ActivationContextConverter activationContextConverter) {
        this.powerAuthClient = powerAuthClient;
        this.httpCustomizationService = httpCustomizationService;
        this.activationContextConverter = activationContextConverter;
    }

    /**
     * Set application configuration class via setter injection.
     * @param applicationConfiguration Application configuration.
     */
    @Autowired(required = false)
    public void setApplicationConfiguration(PowerAuthApplicationConfiguration applicationConfiguration) {
        this.applicationConfiguration = applicationConfiguration;
    }

    /**
     * Set PowerAuth activation provider via setter injection.
     * @param activationProvider PowerAuth activation provider.
     */
    @Autowired(required = false)
    public void setPowerAuthActivationProvider(CustomActivationProvider activationProvider) {
        this.activationProvider = activationProvider;
    }

    /**
     * Set user info provider via setter injection.
     * @param userInfoProvider User info provider.
     */
    @Autowired(required = false)
    public void setUserInfoProvider(UserInfoProvider userInfoProvider) {
        this.userInfoProvider = userInfoProvider;
    }

    /**
     * Create activation.
     *
     * @param request Create activation layer 1 request.
     * @param eciesContext PowerAuth ECIES encryption context.
     * @return Create activation layer 1 response.
     * @throws PowerAuthActivationException In case create activation fails.
     * @throws PowerAuthRecoveryException In case activation recovery fails.
     */
    public ActivationLayer1Response createActivation(ActivationLayer1Request request, EciesEncryptionContext eciesContext) throws PowerAuthActivationException, PowerAuthRecoveryException {
        try {

            final String applicationKey = eciesContext.getApplicationKey();
            final EciesEncryptedRequest activationData = request.getActivationData();
            final String ephemeralPublicKey = activationData.getEphemeralPublicKey();
            final String encryptedData = activationData.getEncryptedData();
            final String mac = activationData.getMac();
            final String nonce = activationData.getNonce();
            final Map<String, String> identity = request.getIdentityAttributes();
            final Map<String, Object> customAttributes = (request.getCustomAttributes() != null) ? request.getCustomAttributes() : new HashMap<>();

            // Validate inner encryption
            if (nonce == null && !"3.0".equals(eciesContext.getVersion())) {
                logger.warn("Missing nonce for protocol version: {}", eciesContext.getVersion());
                throw new PowerAuthActivationException();
            }

            switch (request.getType()) {
                // Regular activation which uses "code" identity attribute
                case CODE: {

                    // Check if identity attributes are present
                    if (identity == null || identity.isEmpty()) {
                        logger.warn("Identity attributes are missing for code activation");
                        throw new PowerAuthActivationException();
                    }

                    // Extract data from request and encryption object
                    final String activationCode = identity.get("code");

                    if (activationCode == null || activationCode.isEmpty()) {
                        logger.warn("Activation code is missing");
                        throw new PowerAuthActivationException();
                    }

                    // Create context for passing parameters between activation provider calls
                    final Map<String, Object> context = new LinkedHashMap<>();

                    // Call PrepareActivation method on PA server
                    final PrepareActivationRequest prepareRequest = new PrepareActivationRequest();
                    prepareRequest.setActivationCode(activationCode);
                    prepareRequest.setApplicationKey(applicationKey);
                    prepareRequest.setGenerateRecoveryCodes(shouldGenerateRecoveryCodes(identity, customAttributes, context));
                    prepareRequest.setEphemeralPublicKey(ephemeralPublicKey);
                    prepareRequest.setEncryptedData(encryptedData);
                    prepareRequest.setMac(mac);
                    prepareRequest.setNonce(nonce);
                    final PrepareActivationResponse response = powerAuthClient.prepareActivation(
                            prepareRequest,
                            httpCustomizationService.getQueryParams(),
                            httpCustomizationService.getHttpHeaders()
                    );

                    final String userId = response.getUserId();
                    final String activationId = response.getActivationId();
                    final String applicationId = response.getApplicationId();

                    // Process user info
                    Map<String, Object> userInfo = null;
                    if (userInfoProvider != null) {
                        final UserInfoContext userInfoContext = UserInfoContext.builder()
                                .stage(UserInfoStage.ACTIVATION_PROCESS_ACTIVATION_CODE)
                                .userId(userId)
                                .activationId(activationId)
                                .applicationId(applicationId)
                                .build();
                        if (userInfoProvider.shouldReturnUserInfo(userInfoContext)) {
                            userInfo = userInfoProvider.fetchUserClaimsForUserId(userInfoContext);
                        }
                    }

                    Map<String, Object> processedCustomAttributes = customAttributes;
                    // In case a custom activation provider is enabled, process custom attributes and save any flags
                    if (activationProvider != null) {
                        processedCustomAttributes = activationProvider.processCustomActivationAttributes(customAttributes, activationId, userId, applicationId, ActivationType.CODE, context);
                        final List<String> activationFlags = activationProvider.getActivationFlags(identity, processedCustomAttributes, activationId, userId, applicationId, ActivationType.CODE, context);
                        if (activationFlags != null && !activationFlags.isEmpty()) {
                            final AddActivationFlagsRequest flagsRequest = new AddActivationFlagsRequest();
                            flagsRequest.setActivationId(activationId);
                            flagsRequest.getActivationFlags().addAll(activationFlags);
                            powerAuthClient.addActivationFlags(
                                    flagsRequest,
                                    httpCustomizationService.getQueryParams(),
                                    httpCustomizationService.getHttpHeaders()
                            );
                        }
                    }

                    boolean notifyActivationCommit = false;
                    if (response.getActivationStatus() == ActivationStatus.ACTIVE) {
                        // Activation was committed instantly due to presence of Activation OTP.
                        notifyActivationCommit = true;
                    } else {
                        // Otherwise check if activation should be committed instantly and if yes, perform commit.
                        if (activationProvider != null && activationProvider.shouldAutoCommitActivation(identity, customAttributes, activationId, userId, applicationId, ActivationType.CODE, context)) {
                            final CommitActivationRequest commitRequest = new CommitActivationRequest();
                            commitRequest.setActivationId(activationId);
                            commitRequest.setExternalUserId(null);
                            final CommitActivationResponse commitResponse = powerAuthClient.commitActivation(
                                    commitRequest,
                                    httpCustomizationService.getQueryParams(),
                                    httpCustomizationService.getHttpHeaders()
                            );

                            notifyActivationCommit = commitResponse.isActivated();
                        }
                    }
                    // Notify activation provider about an activation commit.
                    if (activationProvider != null && notifyActivationCommit) {
                        activationProvider.activationWasCommitted(identity, customAttributes, activationId, userId, applicationId, ActivationType.CODE, context);
                    }

                    // Prepare and return encrypted response
                    return prepareEncryptedResponse(response.getEncryptedData(), response.getMac(), processedCustomAttributes, userInfo);
                }

                // Custom activation
                case CUSTOM: {
                    // Check if there is a custom activation provider available, return an error in case it is not available.
                    // Only for CUSTOM activations, proceeding without an activation provider does not make a sensible use-case.
                    if (activationProvider == null) {
                        logger.warn("Activation provider is not available");
                        throw new PowerAuthActivationException();
                    }

                    // Check if identity attributes are present
                    if (identity == null || identity.isEmpty()) {
                        logger.warn("Identity attributes are missing for custom activation");
                        throw new PowerAuthActivationException();
                    }

                    // Create context for passing parameters between activation provider calls
                    final Map<String, Object> context = new LinkedHashMap<>();

                    // Lookup user ID using a provided identity attributes
                    final String userId = activationProvider.lookupUserIdForAttributes(identity, context);

                    // If no user was found or user ID is invalid, return an error
                    if (userId == null || userId.equals("") || userId.length() > 255) {
                        logger.warn("Invalid user ID: {}", userId);
                        throw new PowerAuthActivationException();
                    }

                    // Decide if the recovery codes should be generated
                    final Boolean shouldGenerateRecoveryCodes = activationProvider.shouldCreateRecoveryCodes(identity, customAttributes, ActivationType.CODE, context);

                    // Resolve maxFailedCount and activationExpireTimestamp parameters, null value means use value configured on PowerAuth server
                    final Integer maxFailed = activationProvider.getMaxFailedAttemptCount(identity, customAttributes, userId, ActivationType.CUSTOM, context);
                    final Long maxFailedCount = maxFailed == null ? null : maxFailed.longValue();
                    final Long activationValidityPeriod = activationProvider.getValidityPeriodDuringActivation(identity, customAttributes, userId, ActivationType.CUSTOM, context);
                    Date activationExpire = null;
                    if (activationValidityPeriod != null) {
                        final Instant expiration = Instant.now().plusMillis(activationValidityPeriod);
                        activationExpire = Date.from(expiration);
                    }

                    // Create activation for a looked up user and application related to the given application key
                    final CreateActivationRequest createRequest = new CreateActivationRequest();
                    createRequest.setUserId(userId);
                    createRequest.setTimestampActivationExpire(activationExpire);
                    createRequest.setGenerateRecoveryCodes(shouldGenerateRecoveryCodes);
                    createRequest.setMaxFailureCount(maxFailedCount);
                    createRequest.setApplicationKey(applicationKey);
                    createRequest.setEphemeralPublicKey(ephemeralPublicKey);
                    createRequest.setEncryptedData(encryptedData);
                    createRequest.setMac(mac);
                    createRequest.setNonce(nonce);
                    final CreateActivationResponse response = powerAuthClient.createActivation(
                            createRequest,
                            httpCustomizationService.getQueryParams(),
                            httpCustomizationService.getHttpHeaders()
                    );

                    final String activationId = response.getActivationId();
                    final String applicationId = response.getApplicationId();

                    // Process user info
                    Map<String, Object> userInfo = null;
                    if (userInfoProvider != null) {
                        final UserInfoContext userInfoContext = UserInfoContext.builder()
                                .stage(UserInfoStage.ACTIVATION_PROCESS_CUSTOM)
                                .userId(userId)
                                .activationId(activationId)
                                .applicationId(applicationId)
                                .build();
                        if (userInfoProvider.shouldReturnUserInfo(userInfoContext)) {
                            userInfo = userInfoProvider.fetchUserClaimsForUserId(userInfoContext);
                        }
                    }

                    // Process custom attributes using a custom logic
                    final Map<String, Object> processedCustomAttributes = activationProvider.processCustomActivationAttributes(customAttributes, activationId, userId, applicationId, ActivationType.CUSTOM, context);

                    // Save activation flags in case the provider specified any flags
                    final List<String> activationFlags = activationProvider.getActivationFlags(identity, processedCustomAttributes, activationId, userId, applicationId, ActivationType.CUSTOM, context);
                    if (activationFlags != null && !activationFlags.isEmpty()) {
                        final AddActivationFlagsRequest flagsRequest = new AddActivationFlagsRequest();
                        flagsRequest.setActivationId(activationId);
                        flagsRequest.getActivationFlags().addAll(activationFlags);
                        powerAuthClient.addActivationFlags(
                                flagsRequest,
                                httpCustomizationService.getQueryParams(),
                                httpCustomizationService.getHttpHeaders()
                        );
                    }

                    // Check if activation should be committed instantly and if yes, perform commit
                    if (activationProvider.shouldAutoCommitActivation(identity, customAttributes, activationId, userId, applicationId, ActivationType.CUSTOM, context)) {
                        final CommitActivationRequest commitRequest = new CommitActivationRequest();
                        commitRequest.setActivationId(activationId);
                        commitRequest.setExternalUserId(null);
                        final CommitActivationResponse commitResponse = powerAuthClient.commitActivation(
                                commitRequest,
                                httpCustomizationService.getQueryParams(),
                                httpCustomizationService.getHttpHeaders()
                        );
                        if (commitResponse.isActivated()) {
                            activationProvider.activationWasCommitted(identity, customAttributes, activationId, userId, applicationId, ActivationType.CUSTOM, context);
                        }
                    }

                    // Prepare encrypted activation data
                    return prepareEncryptedResponse(response.getEncryptedData(), response.getMac(), processedCustomAttributes, userInfo);
                }

                // Activation using recovery code
                case RECOVERY: {

                    // Check if identity attributes are present
                    if (identity == null || identity.isEmpty()) {
                        logger.warn("Identity attributes are missing for activation recovery");
                        throw new PowerAuthActivationException();
                    }

                    // Extract data from request and encryption object
                    final String recoveryCode = identity.get("recoveryCode");
                    final String recoveryPuk = identity.get("puk");

                    if (recoveryCode == null || recoveryCode.isEmpty()) {
                        logger.warn("Recovery code is missing");
                        throw new PowerAuthActivationException();
                    }

                    if (recoveryPuk == null || recoveryPuk.isEmpty()) {
                        logger.warn("Recovery PUK is missing");
                        throw new PowerAuthActivationException();
                    }

                    // Create context for passing parameters between activation provider calls
                    final Map<String, Object> context = new LinkedHashMap<>();

                    // Resolve maxFailedCount, user ID is not known and decide if the recovery codes should be generated.
                    Long maxFailedCount = null;
                    Boolean shouldGenerateRecoveryCodes = null;
                    if (activationProvider != null) {
                        final Integer maxFailed = activationProvider.getMaxFailedAttemptCount(identity, customAttributes, null, ActivationType.RECOVERY, context);
                        maxFailedCount = maxFailed == null ? null : maxFailed.longValue();
                        shouldGenerateRecoveryCodes = activationProvider.shouldCreateRecoveryCodes(identity, customAttributes, ActivationType.CODE, context);
                    }

                    // Call RecoveryCodeActivation method on PA server
                    final RecoveryCodeActivationRequest recoveryRequest = new RecoveryCodeActivationRequest();
                    recoveryRequest.setRecoveryCode(recoveryCode);
                    recoveryRequest.setPuk(recoveryPuk);
                    recoveryRequest.setGenerateRecoveryCodes(shouldGenerateRecoveryCodes);
                    recoveryRequest.setApplicationKey(applicationKey);
                    recoveryRequest.setMaxFailureCount(maxFailedCount);
                    recoveryRequest.setEphemeralPublicKey(ephemeralPublicKey);
                    recoveryRequest.setEncryptedData(encryptedData);
                    recoveryRequest.setMac(mac);
                    recoveryRequest.setNonce(nonce);
                    final RecoveryCodeActivationResponse response = powerAuthClient.createActivationUsingRecoveryCode(
                            recoveryRequest,
                            httpCustomizationService.getQueryParams(),
                            httpCustomizationService.getHttpHeaders()
                    );

                    final String userId = response.getUserId();
                    final String activationId = response.getActivationId();
                    final String applicationId = response.getApplicationId();

                    // Process user info
                    Map<String, Object> userInfo = null;
                    if (userInfoProvider != null) {
                        final UserInfoContext userInfoContext = UserInfoContext.builder()
                                .stage(UserInfoStage.ACTIVATION_PROCESS_RECOVERY)
                                .userId(userId)
                                .activationId(activationId)
                                .applicationId(applicationId)
                                .build();
                        if (userInfoProvider.shouldReturnUserInfo(userInfoContext)) {
                            userInfo = userInfoProvider.fetchUserClaimsForUserId(userInfoContext);
                        }
                    }

                    Map<String, Object> processedCustomAttributes = customAttributes;
                    // In case a custom activation provider is enabled, process custom attributes and save any flags
                    if (activationProvider != null) {
                        processedCustomAttributes = activationProvider.processCustomActivationAttributes(customAttributes, activationId, userId, applicationId, ActivationType.RECOVERY, context);
                        final List<String> activationFlags = activationProvider.getActivationFlags(identity, processedCustomAttributes, activationId, userId, applicationId, ActivationType.RECOVERY, context);
                        if (activationFlags != null && !activationFlags.isEmpty()) {
                            final AddActivationFlagsRequest flagsRequest = new AddActivationFlagsRequest();
                            flagsRequest.setActivationId(activationId);
                            flagsRequest.getActivationFlags().addAll(activationFlags);
                            powerAuthClient.addActivationFlags(
                                    flagsRequest,
                                    httpCustomizationService.getQueryParams(),
                                    httpCustomizationService.getHttpHeaders()
                            );
                        }
                    }

                    // Automatically commit activation by default, the optional activation provider can override automatic commit
                    if (activationProvider == null || activationProvider.shouldAutoCommitActivation(identity, customAttributes, activationId, userId, applicationId, ActivationType.RECOVERY, context)) {
                        final CommitActivationRequest commitRequest = new CommitActivationRequest();
                        commitRequest.setActivationId(activationId);
                        commitRequest.setExternalUserId(null);
                        final CommitActivationResponse commitResponse = powerAuthClient.commitActivation(
                                commitRequest,
                                httpCustomizationService.getQueryParams(),
                                httpCustomizationService.getHttpHeaders()
                        );
                        if (activationProvider != null && commitResponse.isActivated()) {
                            activationProvider.activationWasCommitted(identity, customAttributes, activationId, userId, applicationId, ActivationType.RECOVERY, context);
                        }
                    }

                    // Prepare and return encrypted response
                    return prepareEncryptedResponse(response.getEncryptedData(), response.getMac(), processedCustomAttributes, userInfo);
                }

                default:
                    logger.warn("Invalid activation request");
                    throw new PowerAuthInvalidRequestException();
            }
        } catch (PowerAuthClientException ex) {
            if (ex.getPowerAuthError() instanceof PowerAuthErrorRecovery) {
                final PowerAuthErrorRecovery errorRecovery = (PowerAuthErrorRecovery) ex.getPowerAuthError();
                logger.debug("Invalid recovery code, current PUK index: {}", errorRecovery.getCurrentRecoveryPukIndex());
                throw new PowerAuthRecoveryException(ex.getMessage(), "INVALID_RECOVERY_CODE", errorRecovery.getCurrentRecoveryPukIndex());
            }
            logger.warn("Creating PowerAuth activation failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthActivationException();
        } catch (PowerAuthActivationException ex) {
            // Do not swallow PowerAuthActivationException for custom activations.
            // See: https://github.com/wultra/powerauth-restful-integration/issues/199
            logger.warn("Creating PowerAuth activation failed, error: {}", ex.getMessage());
            throw ex;
        } catch (Exception ex) {
            logger.warn("Creating PowerAuth activation failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthActivationException();
        }
    }

    private boolean shouldGenerateRecoveryCodes(final Map<String, String> identity, final Map<String, Object> customAttributes, final Map<String, Object> context) throws PowerAuthActivationException {
        if (activationProvider == null) {
            return false;
        }
        return activationProvider.shouldCreateRecoveryCodes(identity, customAttributes, ActivationType.CODE, context);
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
            final String activationId = request.getActivationId();
            final String challenge = request.getChallenge();
            final GetActivationStatusRequest statusRequest = new GetActivationStatusRequest();
            statusRequest.setActivationId(activationId);
            statusRequest.setChallenge(challenge);
            final GetActivationStatusResponse paResponse = powerAuthClient.getActivationStatus(
                    statusRequest,
                    httpCustomizationService.getQueryParams(),
                    httpCustomizationService.getHttpHeaders()
            );
            final ActivationStatusResponse response = new ActivationStatusResponse();
            response.setActivationId(paResponse.getActivationId());
            response.setEncryptedStatusBlob(paResponse.getEncryptedStatusBlob());
            response.setNonce(paResponse.getEncryptedStatusBlobNonce());
            if (applicationConfiguration != null) {
                final ActivationContext activationContext = activationContextConverter.fromActivationDetailResponse(paResponse);
                response.setCustomObject(applicationConfiguration.statusServiceCustomObject(activationContext));
            }
            return response;
        } catch (Exception ex) {
            logger.warn("PowerAuth activation status check failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
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
            final String activationId = apiAuthentication.getActivationContext().getActivationId();
            final String userId = apiAuthentication.getUserId();
            final String applicationId = apiAuthentication.getApplicationId();

            // Call other application specific cleanup logic
            final RemoveActivationResponse paResponse;
            final RemoveActivationRequest removeRequest = new RemoveActivationRequest();
            removeRequest.setActivationId(activationId);
            removeRequest.setExternalUserId(null);
            if (activationProvider != null) {
                // revoke recovery codes
                final boolean revokeCodes = activationProvider.shouldRevokeRecoveryCodeOnRemove(activationId, userId, applicationId);
                removeRequest.setRevokeRecoveryCodes(revokeCodes);
                paResponse = powerAuthClient.removeActivation(
                        removeRequest,
                        httpCustomizationService.getQueryParams(),
                        httpCustomizationService.getHttpHeaders()
                );
                activationProvider.activationWasRemoved(activationId, userId, applicationId);
            } else {
                // do not revoke recovery codes
                removeRequest.setRevokeRecoveryCodes(false);
                paResponse = powerAuthClient.removeActivation(
                        removeRequest,
                        httpCustomizationService.getQueryParams(),
                        httpCustomizationService.getHttpHeaders()
                );
            }

            // Prepare and return the response
            final ActivationRemoveResponse response = new ActivationRemoveResponse();
            response.setActivationId(paResponse.getActivationId());
            return response;
        } catch (Exception ex) {
            logger.warn("PowerAuth activation removal failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthActivationException();
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
    private ActivationLayer1Response prepareEncryptedResponse(String encryptedData, String mac, Map<String, Object> processedCustomAttributes, Map<String, Object> userInfo) {
        // Prepare encrypted response object for layer 2
        final EciesEncryptedResponse encryptedResponseL2 = new EciesEncryptedResponse();
        encryptedResponseL2.setEncryptedData(encryptedData);
        encryptedResponseL2.setMac(mac);

        // The response is encrypted once more before sent to client using ResponseBodyAdvice
        final ActivationLayer1Response responseL1 = new ActivationLayer1Response();
        responseL1.setUserInfo(userInfo);
        responseL1.setCustomAttributes(processedCustomAttributes);
        responseL1.setActivationData(encryptedResponseL2);
        return responseL1;
    }

}
