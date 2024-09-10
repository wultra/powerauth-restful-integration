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
import io.getlime.security.powerauth.rest.api.model.request.ActivationRenameRequest;
import io.getlime.security.powerauth.rest.api.model.request.ActivationStatusRequest;
import io.getlime.security.powerauth.rest.api.model.request.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.*;
import io.getlime.security.powerauth.rest.api.spring.application.PowerAuthApplicationConfiguration;
import io.getlime.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.spring.converter.ActivationContextConverter;
import io.getlime.security.powerauth.rest.api.spring.encryption.EncryptionContext;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthActivationException;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthRecoveryException;
import io.getlime.security.powerauth.rest.api.spring.model.ActivationContext;
import io.getlime.security.powerauth.rest.api.spring.model.UserInfoContext;
import io.getlime.security.powerauth.rest.api.spring.provider.CustomActivationProvider;
import io.getlime.security.powerauth.rest.api.spring.provider.UserInfoProvider;
import io.getlime.security.powerauth.rest.api.spring.service.oidc.OidcActivationContext;
import io.getlime.security.powerauth.rest.api.spring.service.oidc.OidcHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

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
@Slf4j
public class ActivationService {

    private static final String METHOD_OIDC = "oidc";

    private final PowerAuthClient powerAuthClient;
    private final HttpCustomizationService httpCustomizationService;
    private final ActivationContextConverter activationContextConverter;
    private final OidcHandler oidcHandler;

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
    public ActivationService(
            PowerAuthClient powerAuthClient,
            HttpCustomizationService httpCustomizationService,
            ActivationContextConverter activationContextConverter,
            OidcHandler oidcHandler) {

        this.powerAuthClient = powerAuthClient;
        this.httpCustomizationService = httpCustomizationService;
        this.activationContextConverter = activationContextConverter;
        this.oidcHandler = oidcHandler;
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
    public ActivationLayer1Response createActivation(ActivationLayer1Request request, EncryptionContext eciesContext) throws PowerAuthActivationException, PowerAuthRecoveryException {
        final ActivationType type = request.getType();
        logger.debug("Handling activation type: {}", type);
        final Map<String, String> identity = request.getIdentityAttributes();

        checkIdentityAttributesPresent(identity);

        try {
            return switch (type) {
                // Regular activation which uses "code" identity attribute
                case CODE -> processCodeActivation(eciesContext, request);
                // Direct activation for known specific methods, otherwise fallback to custom activation
                case CUSTOM, DIRECT -> processDirectOrCustomActivation(eciesContext, request, type, identity);
                case RECOVERY -> processRecoveryCodeActivation(eciesContext, request);
            };
        } catch (PowerAuthClientException ex) {
            if (ex.getPowerAuthError().orElse(null) instanceof final PowerAuthErrorRecovery errorRecovery) {
                logger.debug("Invalid recovery code, current PUK index: {}", errorRecovery.getCurrentRecoveryPukIndex());
                throw new PowerAuthRecoveryException(ex.getMessage(), "INVALID_RECOVERY_CODE", errorRecovery.getCurrentRecoveryPukIndex());
            }
            throw new PowerAuthActivationException("Creating PowerAuth activation failed.", ex);
        } catch (Exception ex) {
            throw new PowerAuthActivationException("Creating PowerAuth activation failed.", ex);
        }
    }

    private ActivationLayer1Response processCodeActivation(final EncryptionContext eciesContext, final ActivationLayer1Request request) throws PowerAuthActivationException, PowerAuthClientException {
        logger.debug("Processing recovery code activation.");

        final Map<String, String> identity = request.getIdentityAttributes();

        // Extract data from request and encryption object
        final String activationCode = identity.get("code");

        if (!StringUtils.hasText(activationCode)) {
            throw new PowerAuthActivationException("Activation code is missing");
        }

        // Create context for passing parameters between activation provider calls
        final Map<String, Object> context = new LinkedHashMap<>();

        final Map<String, Object> customAttributes = Objects.requireNonNullElse(request.getCustomAttributes(), new HashMap<>());

        final EciesEncryptedRequest activationData = request.getActivationData();

        // Call PrepareActivation method on PA server
        final PrepareActivationRequest prepareRequest = new PrepareActivationRequest();
        prepareRequest.setActivationCode(activationCode);
        prepareRequest.setApplicationKey(eciesContext.getApplicationKey());
        prepareRequest.setGenerateRecoveryCodes(shouldGenerateRecoveryCodes(identity, customAttributes, context));
        prepareRequest.setTemporaryKeyId(activationData.getTemporaryKeyId());
        prepareRequest.setEphemeralPublicKey(activationData.getEphemeralPublicKey());
        prepareRequest.setEncryptedData(activationData.getEncryptedData());
        prepareRequest.setMac(activationData.getMac());
        prepareRequest.setNonce(activationData.getNonce());
        prepareRequest.setProtocolVersion(eciesContext.getVersion());
        prepareRequest.setTimestamp(activationData.getTimestamp());

        final PrepareActivationResponse response = powerAuthClient.prepareActivation(
                prepareRequest,
                httpCustomizationService.getQueryParams(),
                httpCustomizationService.getHttpHeaders()
        );

        final String userId = response.getUserId();
        final String activationId = response.getActivationId();
        final String applicationId = response.getApplicationId();

        final UserInfoContext userInfoContext = UserInfoContext.builder()
                .stage(UserInfoStage.ACTIVATION_PROCESS_ACTIVATION_CODE)
                .userId(userId)
                .activationId(activationId)
                .applicationId(applicationId)
                .build();
        final Map<String, Object> userInfo = processUserInfo(userInfoContext);

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
                final CommitActivationResponse commitResponse = commitActivation(activationId);
                notifyActivationCommit = commitResponse.isActivated();
            }
        }
        // Notify activation provider about an activation commit.
        if (activationProvider != null && notifyActivationCommit) {
            activationProvider.activationWasCommitted(identity, customAttributes, activationId, userId, applicationId, ActivationType.CODE, context);
        }

        // Prepare and return encrypted response
        return prepareEncryptedResponse(response.getEncryptedData(), response.getMac(),
                response.getNonce(), response.getTimestamp(), processedCustomAttributes, userInfo);
    }

    private ActivationLayer1Response processRecoveryCodeActivation(final EncryptionContext eciesContext, final ActivationLayer1Request request) throws PowerAuthActivationException, PowerAuthClientException {
        logger.debug("Processing recovery code activation.");

        final Map<String, String> identity = request.getIdentityAttributes();

        // Extract data from request and encryption object
        final String recoveryCode = identity.get("recoveryCode");
        final String recoveryPuk = identity.get("puk");

        if (!StringUtils.hasText(recoveryCode)) {
            throw new PowerAuthActivationException("Recovery code is missing");
        }

        if (!StringUtils.hasText(recoveryPuk)) {
            throw new PowerAuthActivationException("Recovery PUK is missing");
        }

        // Create context for passing parameters between activation provider calls
        final Map<String, Object> context = new LinkedHashMap<>();

        final Map<String, Object> customAttributes = Objects.requireNonNullElse(request.getCustomAttributes(), new HashMap<>());

        // Resolve maxFailedCount, user ID is not known and decide if the recovery codes should be generated.
        Long maxFailedCount = null;
        Boolean shouldGenerateRecoveryCodes = null;
        if (activationProvider != null) {
            final Integer maxFailed = activationProvider.getMaxFailedAttemptCount(identity, customAttributes, null, ActivationType.RECOVERY, context);
            maxFailedCount = maxFailed == null ? null : maxFailed.longValue();
            shouldGenerateRecoveryCodes = activationProvider.shouldCreateRecoveryCodes(identity, customAttributes, ActivationType.CODE, context);
        }

        final EciesEncryptedRequest activationData = request.getActivationData();

        // Call RecoveryCodeActivation method on PA server
        final RecoveryCodeActivationRequest recoveryRequest = new RecoveryCodeActivationRequest();
        recoveryRequest.setRecoveryCode(recoveryCode);
        recoveryRequest.setPuk(recoveryPuk);
        recoveryRequest.setGenerateRecoveryCodes(shouldGenerateRecoveryCodes);
        recoveryRequest.setApplicationKey(eciesContext.getApplicationKey());
        recoveryRequest.setMaxFailureCount(maxFailedCount);
        recoveryRequest.setTemporaryKeyId(activationData.getTemporaryKeyId());
        recoveryRequest.setEphemeralPublicKey(activationData.getEphemeralPublicKey());
        recoveryRequest.setEncryptedData(activationData.getEncryptedData());
        recoveryRequest.setMac(activationData.getMac());
        recoveryRequest.setNonce(activationData.getNonce());
        recoveryRequest.setProtocolVersion(eciesContext.getVersion());
        recoveryRequest.setTimestamp(activationData.getTimestamp());

        final RecoveryCodeActivationResponse response = powerAuthClient.createActivationUsingRecoveryCode(
                recoveryRequest,
                httpCustomizationService.getQueryParams(),
                httpCustomizationService.getHttpHeaders()
        );

        final String userId = response.getUserId();
        final String activationId = response.getActivationId();
        final String applicationId = response.getApplicationId();

        final UserInfoContext userInfoContext = UserInfoContext.builder()
                .stage(UserInfoStage.ACTIVATION_PROCESS_RECOVERY)
                .userId(userId)
                .activationId(activationId)
                .applicationId(applicationId)
                .build();
        final Map<String, Object> userInfo = processUserInfo(userInfoContext);

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
            final CommitActivationResponse commitResponse = commitActivation(activationId);
            if (activationProvider != null && commitResponse.isActivated()) {
                activationProvider.activationWasCommitted(identity, customAttributes, activationId, userId, applicationId, ActivationType.RECOVERY, context);
            }
        }

        // Prepare and return encrypted response
        return prepareEncryptedResponse(response.getEncryptedData(), response.getMac(),
                response.getNonce(), response.getTimestamp(), processedCustomAttributes, userInfo);
    }

    private ActivationLayer1Response processCustomActivation(final EncryptionContext eciesContext, final ActivationLayer1Request request) throws PowerAuthActivationException, PowerAuthClientException {
        logger.debug("Processing custom activation.");

        if (activationProvider == null) {
            throw new PowerAuthActivationException("Activation provider is not available");
        }

        // Create context for passing parameters between activation provider calls
        final Map<String, Object> context = new LinkedHashMap<>();

        final Map<String, String> identity = request.getIdentityAttributes();

        // Lookup user ID using a provided identity attributes
        final String userId = activationProvider.lookupUserIdForAttributes(identity, context);

        // If no user was found or user ID is invalid, return an error
        if (!StringUtils.hasText(userId) || userId.length() > 255) {
            logger.warn("Invalid user ID: {}", userId);
            throw new PowerAuthActivationException();
        }

        final Map<String, Object> customAttributes = Objects.requireNonNullElse(request.getCustomAttributes(), new HashMap<>());

        // Decide if the recovery codes should be generated
        final boolean shouldGenerateRecoveryCodes = activationProvider.shouldCreateRecoveryCodes(identity, customAttributes, ActivationType.CODE, context);

        // Resolve maxFailedCount and activationExpireTimestamp parameters, null value means use value configured on PowerAuth server
        final Integer maxFailed = activationProvider.getMaxFailedAttemptCount(identity, customAttributes, userId, ActivationType.CUSTOM, context);
        final Long maxFailedCount = maxFailed == null ? null : maxFailed.longValue();
        final Long activationValidityPeriod = activationProvider.getValidityPeriodDuringActivation(identity, customAttributes, userId, ActivationType.CUSTOM, context);
        Date activationExpire = null;
        if (activationValidityPeriod != null) {
            final Instant expiration = Instant.now().plusMillis(activationValidityPeriod);
            activationExpire = Date.from(expiration);
        }

        final EciesEncryptedRequest activationData = request.getActivationData();

        // Create activation for a looked up user and application related to the given application key
        final CreateActivationRequest createRequest = new CreateActivationRequest();
        createRequest.setUserId(userId);
        createRequest.setTimestampActivationExpire(activationExpire);
        createRequest.setGenerateRecoveryCodes(shouldGenerateRecoveryCodes);
        createRequest.setMaxFailureCount(maxFailedCount);
        createRequest.setApplicationKey(eciesContext.getApplicationKey());
        createRequest.setTemporaryKeyId(activationData.getTemporaryKeyId());
        createRequest.setEphemeralPublicKey(activationData.getEphemeralPublicKey());
        createRequest.setEncryptedData(activationData.getEncryptedData());
        createRequest.setMac(activationData.getMac());
        createRequest.setNonce(activationData.getNonce());
        createRequest.setProtocolVersion(eciesContext.getVersion());
        createRequest.setTimestamp(activationData.getTimestamp());
        final CreateActivationResponse response = powerAuthClient.createActivation(
                createRequest,
                httpCustomizationService.getQueryParams(),
                httpCustomizationService.getHttpHeaders()
        );

        final String activationId = response.getActivationId();
        final String applicationId = response.getApplicationId();

        final UserInfoContext userInfoContext = UserInfoContext.builder()
                .stage(UserInfoStage.ACTIVATION_PROCESS_CUSTOM)
                .userId(userId)
                .activationId(activationId)
                .applicationId(applicationId)
                .build();
        final Map<String, Object> userInfo = processUserInfo(userInfoContext);

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
            final CommitActivationResponse commitResponse = commitActivation(activationId);
            if (commitResponse.isActivated()) {
                activationProvider.activationWasCommitted(identity, customAttributes, activationId, userId, applicationId, ActivationType.CUSTOM, context);
            }
        }

        // Prepare encrypted activation data
        return prepareEncryptedResponse(response.getEncryptedData(), response.getMac(),
                response.getNonce(), response.getTimestamp(), processedCustomAttributes, userInfo);
    }

    private ActivationLayer1Response processDirectOrCustomActivation(final EncryptionContext eciesContext, final ActivationLayer1Request request, final ActivationType type, final Map<String, String> identity) throws PowerAuthActivationException, PowerAuthClientException {
        if (type == ActivationType.DIRECT) {
            final String method = identity.get("method");
            if (METHOD_OIDC.equals(method)) {
                return processOidcActivation(eciesContext, request);
            } else {
                logger.info("Unknown method: {} of direct activation, fallback to custom activation", method);
            }
        }

        return processCustomActivation(eciesContext, request);
    }

    private ActivationLayer1Response processOidcActivation(final EncryptionContext eciesContext, final ActivationLayer1Request request) throws PowerAuthClientException, PowerAuthActivationException {
        logger.debug("Processing direct OIDC activation.");

        final Map<String, String> identity = request.getIdentityAttributes();
        final OidcActivationContext oAuthActivationContext = OidcActivationContext.builder()
                .providerId(identity.get("providerId"))
                .code(identity.get("code"))
                .nonce(identity.get("nonce"))
                .codeVerifier(identity.get("codeVerifier"))
                .applicationKey(eciesContext.getApplicationKey())
                .build();

        final String userId = oidcHandler.retrieveUserId(oAuthActivationContext);

        // Create context for passing parameters between activation provider calls
        final Map<String, Object> context = new LinkedHashMap<>();

        final EciesEncryptedRequest activationData = request.getActivationData();
        final Map<String, Object> customAttributes = Objects.requireNonNullElse(request.getCustomAttributes(), new HashMap<>());

        final CreateActivationRequest createRequest = new CreateActivationRequest();
        createRequest.setUserId(userId);
        createRequest.setGenerateRecoveryCodes(shouldGenerateRecoveryCodes(identity, customAttributes, context));
        createRequest.setApplicationKey(eciesContext.getApplicationKey());
        createRequest.setTemporaryKeyId(activationData.getTemporaryKeyId());
        createRequest.setEphemeralPublicKey(activationData.getEphemeralPublicKey());
        createRequest.setEncryptedData(activationData.getEncryptedData());
        createRequest.setMac(activationData.getMac());
        createRequest.setNonce(activationData.getNonce());
        createRequest.setProtocolVersion(eciesContext.getVersion());
        createRequest.setTimestamp(activationData.getTimestamp());

        final CreateActivationResponse response = powerAuthClient.createActivation(
                createRequest,
                httpCustomizationService.getQueryParams(),
                httpCustomizationService.getHttpHeaders()
        );

        final String activationId = response.getActivationId();
        final String applicationId = response.getApplicationId();

        commitActivation(activationId);

        final UserInfoContext userInfoContext = UserInfoContext.builder()
                .stage(UserInfoStage.ACTIVATION_PROCESS_CUSTOM)
                .userId(userId)
                .activationId(activationId)
                .applicationId(applicationId)
                .build();
        final Map<String, Object> userInfo = processUserInfo(userInfoContext);

        return prepareEncryptedResponse(response.getEncryptedData(), response.getMac(),
                response.getNonce(), response.getTimestamp(), customAttributes, userInfo);
    }

    private static void checkIdentityAttributesPresent(final Map<String, String> identity) throws PowerAuthActivationException {
        if (CollectionUtils.isEmpty(identity)) {
            throw new PowerAuthActivationException("Identity attributes are missing for activation.");
        }
    }

    private CommitActivationResponse commitActivation(final String activationId) throws PowerAuthClientException {
        final CommitActivationRequest commitRequest = new CommitActivationRequest();
        commitRequest.setActivationId(activationId);
        commitRequest.setExternalUserId(null);
        return powerAuthClient.commitActivation(
                commitRequest,
                httpCustomizationService.getQueryParams(),
                httpCustomizationService.getHttpHeaders()
        );
    }

    private Map<String, Object> processUserInfo(final UserInfoContext userInfoContext) {
        if (userInfoProvider != null && userInfoProvider.shouldReturnUserInfo(userInfoContext)) {
            return userInfoProvider.fetchUserClaimsForUserId(userInfoContext);
        }
        return null;
    }

    private boolean shouldGenerateRecoveryCodes(final Map<String, String> identity, final Map<String, Object> customAttributes, final Map<String, Object> context) throws PowerAuthActivationException {
        if (activationProvider == null) {
            return true;
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
     * Get activation detail.
     *
     * @param activationId Activation ID.
     * @return Activation detail response.
     * @throws PowerAuthActivationException In case retrieving activation detail fails.
     */
    public ActivationDetailResponse getActivationDetail(String activationId) throws PowerAuthActivationException {
        try {
            final GetActivationStatusRequest statusRequest = new GetActivationStatusRequest();
            statusRequest.setActivationId(activationId);
            final GetActivationStatusResponse paResponse = powerAuthClient.getActivationStatus(
                    statusRequest,
                    httpCustomizationService.getQueryParams(),
                    httpCustomizationService.getHttpHeaders()
            );
            final ActivationDetailResponse response = new ActivationDetailResponse();
            response.setActivationId(paResponse.getActivationId());
            response.setActivationName(paResponse.getActivationName());
            return response;
        } catch (Exception ex) {
            logger.warn("PowerAuth activation status check failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthActivationException();
        }
    }

    /**
     * Rename activation.
     *
     * @param activationId Activation ID to be renamed.
     * @param request      Request with the new activation name.
     * @return Activation detail of the newly named activation.
     * @throws PowerAuthActivationException In case renaming activation fails.
     */
    public ActivationDetailResponse renameActivation(String activationId, ActivationRenameRequest request) throws PowerAuthActivationException {
        try {
            final UpdateActivationNameRequest updateNameRequest = new UpdateActivationNameRequest();
            updateNameRequest.setActivationId(activationId);
            updateNameRequest.setActivationName(request.getActivationName());
            final UpdateActivationNameResponse paResponse = powerAuthClient.updateActivationName(
                    updateNameRequest,
                    httpCustomizationService.getQueryParams(),
                    httpCustomizationService.getHttpHeaders()
            );
            final ActivationDetailResponse response = new ActivationDetailResponse();
            response.setActivationId(paResponse.getActivationId());
            response.setActivationName(paResponse.getActivationName());
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
    private ActivationLayer1Response prepareEncryptedResponse(String encryptedData, String mac, String nonce, Long timestamp, Map<String, Object> processedCustomAttributes, Map<String, Object> userInfo) {
        // Prepare encrypted response object for layer 2
        final EciesEncryptedResponse encryptedResponseL2 = new EciesEncryptedResponse();
        encryptedResponseL2.setEncryptedData(encryptedData);
        encryptedResponseL2.setMac(mac);
        encryptedResponseL2.setNonce(nonce);
        encryptedResponseL2.setTimestamp(timestamp);

        // The response is encrypted once more before sent to client using ResponseBodyAdvice
        final ActivationLayer1Response responseL1 = new ActivationLayer1Response();
        responseL1.setUserInfo(userInfo);
        responseL1.setCustomAttributes(processedCustomAttributes);
        responseL1.setActivationData(encryptedResponseL2);
        return responseL1;
    }

}
