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
package io.getlime.security.powerauth.rest.api.spring.controller.v3;

import com.google.common.io.BaseEncoding;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.powerauth.soap.v3.GetActivationStatusResponse;
import io.getlime.powerauth.soap.v3.PrepareActivationResponse;
import io.getlime.powerauth.soap.v3.RemoveActivationResponse;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.rest.api.base.application.PowerAuthApplicationConfiguration;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.encryption.PowerAuthEciesEncryption;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthActivationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.base.filter.PowerAuthRequestFilterBase;
import io.getlime.security.powerauth.rest.api.model.request.v2.ActivationStatusRequest;
import io.getlime.security.powerauth.rest.api.model.request.v3.ActivationLayer1Request;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v2.ActivationRemoveResponse;
import io.getlime.security.powerauth.rest.api.model.response.v2.ActivationStatusResponse;
import io.getlime.security.powerauth.rest.api.model.response.v3.ActivationLayer1Response;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import io.getlime.security.powerauth.rest.api.spring.annotation.EncryptedRequestBody;
import io.getlime.security.powerauth.rest.api.spring.annotation.PowerAuthEncryption;
import io.getlime.security.powerauth.rest.api.spring.provider.PowerAuthAuthenticationProvider;
import io.getlime.security.powerauth.soap.spring.client.PowerAuthServiceClient;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

/**
 * Controller implementing activation related end-points from the PowerAuth
 * Standard API.
 *
 * <h5>PowerAuth protocol versions:</h5>
 * <ul>
 *     <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@RestController("ActivationControllerV3")
@RequestMapping(value = "/pa/v3/activation")
public class ActivationController {

    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(ActivationController.class);

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

    @RequestMapping(value = "create", method = RequestMethod.POST)
    @PowerAuthEncryption
    public ActivationLayer1Response createActivation(@EncryptedRequestBody ActivationLayer1Request request,
                                                     PowerAuthEciesEncryption eciesEncryption) throws PowerAuthAuthenticationException {

        if (eciesEncryption == null) {
            throw new PowerAuthAuthenticationException("ECIES object is missing");
        }
        try {

            switch (request.getType()) {
                // Regular activation which uses "code" identity attribute
                case CODE:
                    // Extract data from request and encryption object
                    String activationCode = request.getIdentityAttributes().get("code");
                    String applicationKey = eciesEncryption.getApplicationKey();
                    EciesEncryptedRequest activationData = request.getActivationData();
                    String ephemeralPublicKey = activationData.getEphemeralPublicKey();
                    String encryptedData = activationData.getEncryptedData();
                    String mac = activationData.getMac();

                    // Call PrepareActivation SOAP method on PA server
                    PrepareActivationResponse response = powerAuthClient.prepareActivation(activationCode, applicationKey, ephemeralPublicKey, encryptedData, mac);

                    // Prepare encrypted response object for layer 2
                    EciesEncryptedResponse encryptedResponseL2 = new EciesEncryptedResponse();
                    encryptedResponseL2.setEncryptedData(response.getEncryptedData());
                    encryptedResponseL2.setMac(response.getMac());

                    // The response is encrypted once more before sent to client using ResponseBodyAdvice
                    ActivationLayer1Response responseL1 = new ActivationLayer1Response();
                    responseL1.setActivationData(encryptedResponseL2);
                    return responseL1;

                // Custom activation
                case CUSTOM:
                    throw new IllegalStateException("Not implemented yet");

                default:
                    throw new PowerAuthAuthenticationException("Unsupported activation type: "+request.getType());
            }
        } catch (Exception ex) {
            logger.warn("Creating PowerAuth activation failed.", ex);
            throw new PowerAuthAuthenticationException(ex.getMessage());
        }
    }

    /**
     * Get activation status.
     * @param request PowerAuth RESTful request with {@link ActivationStatusRequest} payload.
     * @return PowerAuth RESTful response with {@link ActivationStatusResponse} payload.
     * @throws PowerAuthActivationException In case request fails.
     */
    @RequestMapping(value = "status", method = RequestMethod.POST)
    public ObjectResponse<ActivationStatusResponse> getActivationStatus(@RequestBody ObjectRequest<ActivationStatusRequest> request)
            throws PowerAuthActivationException {
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
            logger.warn("PowerAuth activation status check failed.", ex);
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
            @RequestHeader(value = PowerAuthSignatureHttpHeader.HEADER_NAME) String signatureHeader,
            HttpServletRequest httpServletRequest)
            throws PowerAuthActivationException, PowerAuthAuthenticationException {
        try {
            String requestBodyString = ((String) httpServletRequest.getAttribute(PowerAuthRequestFilterBase.POWERAUTH_SIGNATURE_BASE_STRING));
            byte[] requestBodyBytes = requestBodyString == null ? null : BaseEncoding.base64().decode(requestBodyString);
            PowerAuthApiAuthentication apiAuthentication = authenticationProvider.validateRequestSignature("POST", requestBodyBytes, "/pa/activation/remove", signatureHeader);
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
            logger.warn("PowerAuth activation removal failed.", ex);
            throw new PowerAuthActivationException();
        }
    }
}
