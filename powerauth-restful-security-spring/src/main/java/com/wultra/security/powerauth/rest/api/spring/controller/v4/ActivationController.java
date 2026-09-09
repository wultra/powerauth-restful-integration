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
package com.wultra.security.powerauth.rest.api.spring.controller.v4;

import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.core.rest.model.base.response.Response;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.http.PowerAuthAuthorizationHttpHeader;
import com.wultra.security.powerauth.rest.api.model.request.ActivationConfirmRequest;
import com.wultra.security.powerauth.rest.api.model.request.ActivationRenameRequest;
import com.wultra.security.powerauth.rest.api.model.request.v4.ActivationStatusRequest;
import com.wultra.security.powerauth.rest.api.model.request.v4.ActivationLayer1Request;
import com.wultra.security.powerauth.rest.api.model.response.ActivationDetailResponse;
import com.wultra.security.powerauth.rest.api.model.response.ActivationRemoveResponse;
import com.wultra.security.powerauth.rest.api.model.response.v4.ActivationStatusResponse;
import com.wultra.security.powerauth.rest.api.model.response.v4.ActivationLayer1Response;
import com.wultra.security.powerauth.rest.api.spring.annotation.EncryptedRequestBody;
import com.wultra.security.powerauth.rest.api.spring.annotation.PowerAuth;
import com.wultra.security.powerauth.rest.api.spring.annotation.PowerAuthEncryption;
import com.wultra.security.powerauth.rest.api.spring.annotation.PowerAuthToken;
import com.wultra.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import com.wultra.security.powerauth.rest.api.spring.config.ServiceConfiguration;
import com.wultra.security.powerauth.rest.api.spring.encryption.EncryptionContext;
import com.wultra.security.powerauth.rest.api.spring.encryption.EncryptionScope;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthActivationException;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthEncryptionException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthCodeInvalidException;
import com.wultra.security.powerauth.rest.api.spring.model.ActivationStatus;
import com.wultra.security.powerauth.rest.api.spring.provider.PowerAuthAuthenticationProvider;
import com.wultra.security.powerauth.rest.api.spring.service.v4.ActivationService;
import com.wultra.security.powerauth.rest.api.spring.util.PowerAuthAuthenticationUtil;
import com.wultra.security.powerauth.rest.api.spring.util.PowerAuthVersionUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

/**
 * Controller implementing activation related end-points from the PowerAuth
 * Standard API.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>4.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@RestController("activationControllerV4")
@RequestMapping("/pa/v4/activation")
@AllArgsConstructor
@Validated
@Slf4j
public class ActivationController {

    private PowerAuthAuthenticationProvider authenticationProvider;
    private ActivationService activationServiceV4;
    private ServiceConfiguration serviceConfiguration;

    /**
     * Create activation.
     * @param request Encrypted activation layer 1 request.
     * @param context Encryption context.
     * @return Activation layer 1 response.
     * @throws PowerAuthActivationException In case activation fails.
     */
    @PostMapping("create")
    @PowerAuthEncryption(scope = EncryptionScope.APPLICATION_SCOPE)
    public ActivationLayer1Response createActivation(@Valid @EncryptedRequestBody ActivationLayer1Request request,
                                                     EncryptionContext context) throws PowerAuthActivationException {
        logger.info("action: createActivation, state: initiated");
        if (request == null || context == null) {
            logger.warn("Invalid request in activation create");
            throw new PowerAuthActivationException();
        }
        final ActivationLayer1Response response = activationServiceV4.createActivation(request, context);
        logger.info("action: createActivation, state: succeeded");
        return response;
    }

    /**
     * Get activation status.
     * @param request PowerAuth RESTful request with {@link ActivationStatusRequest} payload.
     * @param encryptionContext Encryption context.
     * @return PowerAuth RESTful response with {@link ActivationStatusResponse} payload.
     * @throws PowerAuthActivationException In case request fails.
     * @throws PowerAuthEncryptionException In case encryption fails.
     */
    @PostMapping("status")
    @PowerAuthEncryption(scope = EncryptionScope.ACTIVATION_SCOPE, allowedStates = { ActivationStatus.ACTIVE, ActivationStatus.PENDING_COMMIT, ActivationStatus.BLOCKED, ActivationStatus.REMOVED })
    public ActivationStatusResponse getActivationStatus(@Valid @EncryptedRequestBody ActivationStatusRequest request, EncryptionContext encryptionContext)
            throws PowerAuthActivationException, PowerAuthEncryptionException {
        logger.info("action: getActivationStatus, state: initiated, activationId: {}",
                encryptionContext != null ? encryptionContext.getActivationId() : null);
        if (request == null) {
            logger.warn("Invalid request object in activation status");
            throw new PowerAuthActivationException();
        }
        if (encryptionContext == null) {
            logger.warn("Invalid encryption context in activation status");
            throw new PowerAuthEncryptionException();
        }
        final ActivationStatusResponse response = activationServiceV4.getActivationStatus(encryptionContext.getActivationId());
        logger.info("action: getActivationStatus, state: succeeded, activationStatus: {}", response.getActivationStatus());
        return response;
    }

    /**
     * Remove activation.
     * @param authHeader PowerAuth authorization HTTP header.
     * @param httpServletRequest HTTP servlet request.
     * @return PowerAuth RESTful response with {@link ActivationRemoveResponse} payload.
     * @throws PowerAuthActivationException In case activation access fails.
     * @throws PowerAuthAuthenticationException In case the authentication code validation fails.
     */
    @PostMapping("remove")
    public ObjectResponse<ActivationRemoveResponse> removeActivation(
            @RequestHeader(value = PowerAuthAuthorizationHttpHeader.HEADER_NAME) String authHeader,
            HttpServletRequest httpServletRequest)
            throws PowerAuthActivationException, PowerAuthAuthenticationException {
        logger.info("action: removeActivation, state: initiated");
        final byte[] requestBodyBytes = authenticationProvider.extractRequestBodyBytes(httpServletRequest);
        final List<PowerAuthCodeType> allowedAuthCodeTypes = new ArrayList<>(
                List.of(
                        PowerAuthCodeType.POSSESSION_KNOWLEDGE,
                        PowerAuthCodeType.POSSESSION_BIOMETRY
                )
        );
        if (serviceConfiguration.isAllowRemoveActivation1fa()) {
            allowedAuthCodeTypes.add(PowerAuthCodeType.POSSESSION);
        }
        final List<ActivationStatus> defaultAllowedStates = List.of(ActivationStatus.ACTIVE);
        final PowerAuthApiAuthentication apiAuthentication = authenticationProvider.validateRequestAuthentication("POST",
                requestBodyBytes, "/pa/activation/remove", authHeader, allowedAuthCodeTypes, defaultAllowedStates);
        if (apiAuthentication == null || apiAuthentication.getActivationContext().getActivationId() == null) {
            logger.debug("Authentication code validation failed");
            throw new PowerAuthCodeInvalidException();
        }
        logger.info("action: removeActivation, state: processing, activationId: {}", apiAuthentication.getActivationContext().getActivationId());
        PowerAuthVersionUtil.checkUnsupportedVersionV4(apiAuthentication.getVersion());

        final ActivationRemoveResponse response = activationServiceV4.removeActivation(apiAuthentication);
        logger.info("action: removeActivation, state: succeeded");
        return new ObjectResponse<>(response);
    }

    /**
     * Fetch activation detail.
     * @param auth PowerAuth authentication.
     * @return Activation detail response.
     * @throws PowerAuthCodeInvalidException In case the authentication code validation fails.
     * @throws PowerAuthInvalidRequestException In case request is invalid.
     * @throws PowerAuthActivationException In case retrieving activation detail fails.
     */
    @PostMapping("detail")
    @PowerAuthToken(authenticationCodeType = {
            PowerAuthCodeType.POSSESSION_BIOMETRY,
            PowerAuthCodeType.POSSESSION_KNOWLEDGE
    })
    @PowerAuthEncryption(scope = EncryptionScope.ACTIVATION_SCOPE)
    public ObjectResponse<ActivationDetailResponse> fetchActivationDetail(PowerAuthApiAuthentication auth) throws PowerAuthCodeInvalidException, PowerAuthInvalidRequestException, PowerAuthActivationException {
        logger.info("action: fetchActivationDetail, state: initiated, activationId: {}",
                auth != null && auth.getActivationContext() != null ? auth.getActivationContext().getActivationId() : null);

        PowerAuthAuthenticationUtil.checkAuthentication(auth);
        PowerAuthVersionUtil.checkUnsupportedVersionV4(auth.getVersion());

        final ActivationDetailResponse activationDetail = activationServiceV4.getActivationDetail(auth.getActivationContext().getActivationId());
        logger.info("action: fetchActivationDetail, state: succeeded");
        return new ObjectResponse<>(activationDetail);
    }

    /**
     * Rename activation.
     * @param request Rename activation request.
     * @param auth PowerAuth authentication.
     * @return Activation detail response.
     * @throws PowerAuthCodeInvalidException In case the authentication code validation fails.
     * @throws PowerAuthInvalidRequestException In case request is invalid.
     * @throws PowerAuthActivationException In case renaming activation fails.
     */
    @PostMapping("rename")
    @PowerAuth(resourceId = "/pa/activation/rename", authenticationCodeType = {
            PowerAuthCodeType.POSSESSION_KNOWLEDGE,
            PowerAuthCodeType.POSSESSION_BIOMETRY
    })
    @PowerAuthEncryption(scope = EncryptionScope.ACTIVATION_SCOPE)
    public ObjectResponse<ActivationDetailResponse> renameActivation(
            @Valid @EncryptedRequestBody ActivationRenameRequest request,
            PowerAuthApiAuthentication auth) throws PowerAuthCodeInvalidException, PowerAuthInvalidRequestException, PowerAuthActivationException {
        logger.info("action: renameActivation, state: initiated, activationId: {}",
                auth != null && auth.getActivationContext() != null ? auth.getActivationContext().getActivationId() : null);

        if (request == null) {
            logger.warn("Invalid request object in activation rename");
            throw new PowerAuthInvalidRequestException();
        }

        PowerAuthAuthenticationUtil.checkAuthentication(auth);
        PowerAuthVersionUtil.checkUnsupportedVersionV4(auth.getVersion());

        final ActivationDetailResponse activationDetail = activationServiceV4.renameActivation(auth.getActivationContext().getActivationId(), request);
        logger.info("action: renameActivation, state: succeeded");
        return new ObjectResponse<>(activationDetail);
    }

    /**
     * Confirm an activation.
     * @param request Confirm activation request.
     * @param auth PowerAuth authentication.
     * @return Response.
     * @throws PowerAuthCodeInvalidException In case the authentication code validation fails.
     * @throws PowerAuthInvalidRequestException In case request is invalid.
     * @throws PowerAuthActivationException In case retrieving activation detail fails.
     */
    @PostMapping("confirm")
    @PowerAuth(resourceId = "/pa/activation/confirm", authenticationCodeType = {
            PowerAuthCodeType.POSSESSION_KNOWLEDGE
    }, allowedStates = {
            ActivationStatus.ACTIVE,
            ActivationStatus.PENDING_COMMIT // The activation may not be committed yet.
    })
    public Response confirmActivation(@Valid @RequestBody ObjectRequest<ActivationConfirmRequest> request, PowerAuthApiAuthentication auth) throws PowerAuthCodeInvalidException, PowerAuthInvalidRequestException, PowerAuthActivationException {
        logger.info("action: confirmActivation, state: initiated, activationId: {}",
                auth != null && auth.getActivationContext() != null ? auth.getActivationContext().getActivationId() : null);

        PowerAuthAuthenticationUtil.checkAuthentication(auth);
        PowerAuthVersionUtil.checkUnsupportedVersionV4(auth.getVersion());

        activationServiceV4.confirmActivation(auth.getActivationContext().getActivationId(), request.getRequestObject().isEnableBiometry());
        logger.info("action: confirmActivation, state: succeeded");
        return new Response();
    }


}
