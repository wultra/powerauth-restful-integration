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
package com.wultra.security.powerauth.rest.api.spring.controller.v3;

import com.wultra.core.rest.model.base.request.ObjectRequest;
import com.wultra.core.rest.model.base.response.ObjectResponse;
import com.wultra.security.powerauth.crypto.lib.enums.PowerAuthCodeType;
import com.wultra.security.powerauth.http.PowerAuthAuthorizationHttpHeader;
import com.wultra.security.powerauth.rest.api.model.request.ActivationRenameRequest;
import com.wultra.security.powerauth.rest.api.model.response.ActivationDetailResponse;
import com.wultra.security.powerauth.rest.api.spring.annotation.PowerAuth;
import com.wultra.security.powerauth.rest.api.spring.annotation.PowerAuthToken;
import com.wultra.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import com.wultra.security.powerauth.rest.api.spring.encryption.EncryptionContext;
import com.wultra.security.powerauth.rest.api.spring.encryption.EncryptionScope;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthActivationException;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthCodeInvalidException;
import com.wultra.security.powerauth.rest.api.model.request.v3.ActivationLayer1Request;
import com.wultra.security.powerauth.rest.api.model.request.v3.ActivationStatusRequest;
import com.wultra.security.powerauth.rest.api.model.response.v3.ActivationLayer1Response;
import com.wultra.security.powerauth.rest.api.model.response.ActivationRemoveResponse;
import com.wultra.security.powerauth.rest.api.model.response.v3.ActivationStatusResponse;
import com.wultra.security.powerauth.rest.api.spring.annotation.EncryptedRequestBody;
import com.wultra.security.powerauth.rest.api.spring.annotation.PowerAuthEncryption;
import com.wultra.security.powerauth.rest.api.spring.provider.PowerAuthAuthenticationProvider;
import com.wultra.security.powerauth.rest.api.spring.service.v3.ActivationService;
import com.wultra.security.powerauth.rest.api.spring.util.PowerAuthAuthenticationUtil;
import com.wultra.security.powerauth.rest.api.spring.util.PowerAuthVersionUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Controller implementing activation related end-points from the PowerAuth
 * Standard API.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 *     <li>3.1</li>
 *     <li>3.2</li>
 *     <li>3.3</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@RestController("activationControllerV3")
@RequestMapping("/pa/v3/activation")
public class ActivationController {

    private static final Logger logger = LoggerFactory.getLogger(ActivationController.class);

    private PowerAuthAuthenticationProvider authenticationProvider;

    private ActivationService activationServiceV3;

    /**
     * Set the activation service via setter injection.
     * @param activationServiceV3 Activation service (v3).
     */
    @Autowired
    public void setActivationServiceV3(ActivationService activationServiceV3) {
        this.activationServiceV3 = activationServiceV3;
    }

    /**
     * Set the authentication provider via setter injection.
     * @param authenticationProvider Authentication provider.
     */
    @Autowired
    public void setAuthenticationProvider(PowerAuthAuthenticationProvider authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
    }

    /**
     * Create activation.
     * @param request Encrypted activation layer 1 request.
     * @param context Encryption context.
     * @return Activation layer 1 response.
     * @throws PowerAuthActivationException In case activation fails.
     */
    @PostMapping("create")
    @PowerAuthEncryption(scope = EncryptionScope.APPLICATION_SCOPE)
    public ActivationLayer1Response createActivation(@EncryptedRequestBody ActivationLayer1Request request,
                                                     EncryptionContext context) throws PowerAuthActivationException {
        if (request == null || context == null) {
            logger.warn("Invalid request in activation create");
            throw new PowerAuthActivationException();
        }
        return activationServiceV3.createActivation(request, context);
    }

    /**
     * Get activation status.
     * @param request PowerAuth RESTful request with {@link ActivationStatusRequest} payload.
     * @return PowerAuth RESTful response with {@link ActivationStatusResponse} payload.
     * @throws PowerAuthActivationException In case request fails.
     */
    @PostMapping("status")
    public ObjectResponse<ActivationStatusResponse> getActivationStatus(@RequestBody ObjectRequest<ActivationStatusRequest> request)
            throws PowerAuthActivationException {
        if (request.getRequestObject() == null || request.getRequestObject().getActivationId() == null) {
            logger.warn("Invalid request object in activation status");
            throw new PowerAuthActivationException();
        }
        ActivationStatusResponse response = activationServiceV3.getActivationStatus(request.getRequestObject());
        return new ObjectResponse<>(response);
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
        byte[] requestBodyBytes = authenticationProvider.extractRequestBodyBytes(httpServletRequest);
        PowerAuthApiAuthentication apiAuthentication = authenticationProvider.validateRequestAuthentication("POST", requestBodyBytes, "/pa/activation/remove", authHeader);
        if (apiAuthentication == null || apiAuthentication.getActivationContext().getActivationId() == null) {
            logger.debug("Authentication code validation failed");
            throw new PowerAuthCodeInvalidException();
        }
        PowerAuthVersionUtil.checkUnsupportedVersionV3(apiAuthentication.getVersion());

        ActivationRemoveResponse response = activationServiceV3.removeActivation(apiAuthentication);
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

        PowerAuthAuthenticationUtil.checkAuthentication(auth);
        PowerAuthVersionUtil.checkUnsupportedVersionV3(auth.getVersion());

        final ActivationDetailResponse activationDetail = activationServiceV3.getActivationDetail(auth.getActivationContext().getActivationId());
        return new ObjectResponse<>(activationDetail);
    }

    /**
     * Remove activation.
     * @param request Remove activation request.
     * @param auth PowerAuth authentication.
     * @return Activation detail response.
     * @throws PowerAuthCodeInvalidException In case the authentication code validation fails.
     * @throws PowerAuthInvalidRequestException In case request is invalid.
     * @throws PowerAuthActivationException In case retrieving activation detail fails.
     */
    @PostMapping("rename")
    @PowerAuth(resourceId = "/pa/activation/rename", authenticationCodeType = {
            PowerAuthCodeType.POSSESSION_KNOWLEDGE,
            PowerAuthCodeType.POSSESSION_BIOMETRY
    })
    @PowerAuthEncryption(scope = EncryptionScope.ACTIVATION_SCOPE)
    public ObjectResponse<ActivationDetailResponse> renameApplication(
            @RequestBody ActivationRenameRequest request,
            PowerAuthApiAuthentication auth) throws PowerAuthCodeInvalidException, PowerAuthInvalidRequestException, PowerAuthActivationException {

        PowerAuthAuthenticationUtil.checkAuthentication(auth);
        PowerAuthVersionUtil.checkUnsupportedVersionV3(auth.getVersion());

        final ActivationDetailResponse activationDetail = activationServiceV3.renameActivation(auth.getActivationContext().getActivationId(), request);
        return new ObjectResponse<>(activationDetail);
    }

}
