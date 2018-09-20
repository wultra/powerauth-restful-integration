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
package io.getlime.security.powerauth.rest.api.spring.controller.v2;

import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.powerauth.soap.v3.GetActivationStatusResponse;
import io.getlime.powerauth.soap.v2.PrepareActivationResponse;
import io.getlime.powerauth.soap.v3.RemoveActivationResponse;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.rest.api.base.application.PowerAuthApplicationConfiguration;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthActivationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.model.request.ActivationCreateRequest;
import io.getlime.security.powerauth.rest.api.model.request.ActivationStatusRequest;
import io.getlime.security.powerauth.rest.api.model.response.ActivationCreateResponse;
import io.getlime.security.powerauth.rest.api.model.response.ActivationRemoveResponse;
import io.getlime.security.powerauth.rest.api.model.response.ActivationStatusResponse;
import io.getlime.security.powerauth.rest.api.spring.provider.PowerAuthAuthenticationProvider;
import io.getlime.security.powerauth.soap.spring.client.PowerAuthServiceClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Controller implementing activation related end-points from the PowerAuth
 * Standard API.
 *
 * <h5>PowerAuth protocol versions:</h5>
 * <ul>
 *     <li>2.0</li>
 *     <li>2.1</li>
 * </ul>
 *
 * @author Petr Dvorak, petr@lime-company.eu
 *
 */
@RestController
@RequestMapping(value = "/pa/activation")
public class ActivationController {

    private PowerAuthServiceClient powerAuthClient;

    private PowerAuthAuthenticationProvider authenticationProvider;

    private PowerAuthApplicationConfiguration applicationConfiguration;

    @Autowired
    public void setPowerAuthClient(PowerAuthServiceClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @Autowired
    public void setAuthenticationProvider(PowerAuthAuthenticationProvider authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
    }

    @Autowired(required = false)
    public void setApplicationConfiguration(PowerAuthApplicationConfiguration applicationConfiguration) {
        this.applicationConfiguration = applicationConfiguration;
    }

    /**
     * Create a new activation.
     * @param request PowerAuth RESTful request with {@link ActivationCreateRequest} payload.
     * @return PowerAuth RESTful response with {@link ActivationCreateResponse} payload.
     * @throws PowerAuthActivationException In case creating activation fails.
     */
    @RequestMapping(value = "create", method = RequestMethod.POST)
    public ObjectResponse<ActivationCreateResponse> createActivation(
            @RequestBody ObjectRequest<ActivationCreateRequest> request
    ) throws PowerAuthActivationException {
        try {
            String activationIDShort = request.getRequestObject().getActivationIdShort();
            String activationNonce = request.getRequestObject().getActivationNonce();
            String cDevicePublicKey = request.getRequestObject().getEncryptedDevicePublicKey();
            String activationName = request.getRequestObject().getActivationName();
            String extras = request.getRequestObject().getExtras();
            String applicationKey = request.getRequestObject().getApplicationKey();
            String applicationSignature = request.getRequestObject().getApplicationSignature();
            String clientEphemeralKey = request.getRequestObject().getEphemeralPublicKey();

            PrepareActivationResponse soapResponse = powerAuthClient.v2().prepareActivation(
                    activationIDShort,
                    activationName,
                    activationNonce,
                    clientEphemeralKey,
                    cDevicePublicKey,
                    extras,
                    applicationKey,
                    applicationSignature
            );

            ActivationCreateResponse response = new ActivationCreateResponse();
            response.setActivationId(soapResponse.getActivationId());
            response.setActivationNonce(soapResponse.getActivationNonce());
            response.setEncryptedServerPublicKey(soapResponse.getEncryptedServerPublicKey());
            response.setEncryptedServerPublicKeySignature(soapResponse.getEncryptedServerPublicKeySignature());
            response.setEphemeralPublicKey(soapResponse.getEphemeralPublicKey());

            return new ObjectResponse<>(response);
        } catch (Exception ex) {
            Logger.getLogger(this.getClass().getName()).log(Level.WARNING, "Creating PowerAuth activation failed.", ex);
            throw new PowerAuthActivationException();
        }
    }

    /**
     * Get activation status.
     * @param request PowerAuth RESTful request with {@link ActivationStatusRequest} payload.
     * @return PowerAuth RESTful response with {@link ActivationStatusResponse} payload.
     * @throws PowerAuthActivationException In case request fails.
     */
    @RequestMapping(value = "status", method = RequestMethod.POST)
    public ObjectResponse<ActivationStatusResponse> getActivationStatus(
            @RequestBody ObjectRequest<ActivationStatusRequest> request
    ) throws PowerAuthActivationException {
        try {
            String activationId = request.getRequestObject().getActivationId();
            GetActivationStatusResponse soapResponse = powerAuthClient.getActivationStatus(activationId);
            ActivationStatusResponse response = new ActivationStatusResponse();
            response.setActivationId(soapResponse.getActivationId());
            response.setEncryptedStatusBlob(soapResponse.getEncryptedStatusBlob());
            if (applicationConfiguration != null) {
                response.setCustomObject(applicationConfiguration.statusServiceCustomObject());
            }
            return new ObjectResponse<>(response);
        } catch (Exception ex) {
            Logger.getLogger(this.getClass().getName()).log(Level.WARNING, "PowerAuth activation status check failed.", ex);
            throw new PowerAuthActivationException();
        }
    }

    /**
     * Get activation status.
     * @param signatureHeader PowerAuth signature HTTP header.
     * @return PowerAuth RESTful response with {@link ActivationRemoveResponse} payload.
     * @throws PowerAuthActivationException In case activation access fails.
     * @throws PowerAuthAuthenticationException In case the signature validation fails.
     */
    @RequestMapping(value = "remove", method = RequestMethod.POST)
    public ObjectResponse<ActivationRemoveResponse> removeActivation(
            @RequestHeader(value = PowerAuthSignatureHttpHeader.HEADER_NAME) String signatureHeader
    ) throws PowerAuthActivationException, PowerAuthAuthenticationException {
        try {
            PowerAuthApiAuthentication apiAuthentication = authenticationProvider.validateRequestSignature("POST", null, "/pa/activation/remove", signatureHeader);
            if (apiAuthentication != null && apiAuthentication.getActivationId() != null) {
                RemoveActivationResponse soapResponse = powerAuthClient.removeActivation(apiAuthentication.getActivationId());
                ActivationRemoveResponse response = new ActivationRemoveResponse();
                response.setActivationId(soapResponse.getActivationId());
                return new ObjectResponse<>(response);
            } else {
                throw new PowerAuthAuthenticationException("USER_NOT_AUTHENTICATED");
            }
        } catch (PowerAuthAuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            Logger.getLogger(this.getClass().getName()).log(Level.WARNING, "PowerAuth activation removal failed.", ex);
            throw new PowerAuthActivationException();
        }
    }

}
