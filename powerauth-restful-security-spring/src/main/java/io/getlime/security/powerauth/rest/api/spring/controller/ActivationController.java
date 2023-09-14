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
package io.getlime.security.powerauth.rest.api.spring.controller;

import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.rest.api.spring.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.spring.encryption.EncryptionContext;
import io.getlime.security.powerauth.rest.api.spring.encryption.EncryptionScope;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthActivationException;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthRecoveryException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthSignatureInvalidException;
import io.getlime.security.powerauth.rest.api.model.request.ActivationLayer1Request;
import io.getlime.security.powerauth.rest.api.model.request.ActivationStatusRequest;
import io.getlime.security.powerauth.rest.api.model.response.ActivationLayer1Response;
import io.getlime.security.powerauth.rest.api.model.response.ActivationRemoveResponse;
import io.getlime.security.powerauth.rest.api.model.response.ActivationStatusResponse;
import io.getlime.security.powerauth.rest.api.spring.annotation.EncryptedRequestBody;
import io.getlime.security.powerauth.rest.api.spring.annotation.PowerAuthEncryption;
import io.getlime.security.powerauth.rest.api.spring.provider.PowerAuthAuthenticationProvider;
import io.getlime.security.powerauth.rest.api.spring.service.ActivationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;

import static io.getlime.security.powerauth.rest.api.spring.util.PowerAuthVersionUtil.checkUnsupportedVersion;

/**
 * Controller implementing activation related end-points from the PowerAuth
 * Standard API.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@RestController("activationControllerV3")
@RequestMapping(value = "/pa/v3/activation")
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
     * @throws PowerAuthRecoveryException In case recovery PUK is invalid.
     */
    @PostMapping("create")
    @PowerAuthEncryption(scope = EncryptionScope.APPLICATION_SCOPE)
    public ActivationLayer1Response createActivation(@EncryptedRequestBody ActivationLayer1Request request,
                                                     EncryptionContext context) throws PowerAuthActivationException, PowerAuthRecoveryException {
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
     * @param signatureHeader PowerAuth signature HTTP header.
     * @param httpServletRequest HTTP servlet request.
     * @return PowerAuth RESTful response with {@link ActivationRemoveResponse} payload.
     * @throws PowerAuthActivationException In case activation access fails.
     * @throws PowerAuthAuthenticationException In case the signature validation fails.
     */
    @PostMapping("remove")
    public ObjectResponse<ActivationRemoveResponse> removeActivation(
            @RequestHeader(value = PowerAuthSignatureHttpHeader.HEADER_NAME) String signatureHeader,
            HttpServletRequest httpServletRequest)
            throws PowerAuthActivationException, PowerAuthAuthenticationException {
        byte[] requestBodyBytes = authenticationProvider.extractRequestBodyBytes(httpServletRequest);
        PowerAuthApiAuthentication apiAuthentication = authenticationProvider.validateRequestSignature("POST", requestBodyBytes, "/pa/activation/remove", signatureHeader);
        if (apiAuthentication == null || apiAuthentication.getActivationContext().getActivationId() == null) {
            logger.debug("Signature validation failed");
            throw new PowerAuthSignatureInvalidException();
        }
        checkUnsupportedVersion(apiAuthentication.getVersion(), PowerAuthInvalidRequestException::new);

        ActivationRemoveResponse response = activationServiceV3.removeActivation(apiAuthentication);
        return new ObjectResponse<>(response);
    }
}
