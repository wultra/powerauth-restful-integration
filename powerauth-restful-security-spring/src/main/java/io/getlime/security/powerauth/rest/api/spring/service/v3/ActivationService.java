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

import io.getlime.powerauth.soap.v3.GetActivationStatusResponse;
import io.getlime.powerauth.soap.v3.PrepareActivationResponse;
import io.getlime.powerauth.soap.v3.RemoveActivationResponse;
import io.getlime.security.powerauth.rest.api.base.application.PowerAuthApplicationConfiguration;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.encryption.PowerAuthEciesEncryption;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthActivationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
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

/**
 * Service implementing activation functionality.
 *
 * <h5>PowerAuth protocol versions:</h5>
 * <ul>
 *     <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@Service("ActivationServiceV3")
public class ActivationService {

    private PowerAuthServiceClient powerAuthClient;

    private PowerAuthApplicationConfiguration applicationConfiguration;

    private static final Logger logger = LoggerFactory.getLogger(ActivationService.class);

    @Autowired
    public void setPowerAuthClient(PowerAuthServiceClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @Autowired(required = false)
    public void setApplicationConfiguration(PowerAuthApplicationConfiguration applicationConfiguration) {
        this.applicationConfiguration = applicationConfiguration;
    }

    /**
     * Create activation.
     * @param request Create activation layer 1 request.
     * @param eciesEncryption PowerAuth ECIES encryption object.
     * @return Create activation layer 1 response.
     * @throws PowerAuthActivationException In case create activation fails.
     */
    public ActivationLayer1Response createActivation(ActivationLayer1Request request, PowerAuthEciesEncryption eciesEncryption) throws PowerAuthActivationException {
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
            logger.warn("Creating PowerAuth activation failed", ex);
            throw new PowerAuthActivationException();
        }
    }

    /**
     * Get activation status.
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
     * @param apiAuthentication PowerAuth API authentication object.
     * @return Activation remove response.
     * @throws PowerAuthActivationException In case remove activation fails.
     * @throws PowerAuthAuthenticationException In case authentication fails.
     */
    public ActivationRemoveResponse removeActivation(PowerAuthApiAuthentication apiAuthentication) throws PowerAuthActivationException, PowerAuthAuthenticationException {
        try {
            if (apiAuthentication != null && apiAuthentication.getActivationId() != null) {
                RemoveActivationResponse soapResponse = powerAuthClient.removeActivation(apiAuthentication.getActivationId());
                ActivationRemoveResponse response = new ActivationRemoveResponse();
                response.setActivationId(soapResponse.getActivationId());
                return response;
            } else {
                throw new PowerAuthAuthenticationException("USER_NOT_AUTHENTICATED");
            }
        } catch (PowerAuthAuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            logger.warn("PowerAuth activation removal failed", ex);
            throw new PowerAuthActivationException();
        }
    }
}
