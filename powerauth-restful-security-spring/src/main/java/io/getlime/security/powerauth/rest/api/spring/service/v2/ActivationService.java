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
package io.getlime.security.powerauth.rest.api.spring.service.v2;

import io.getlime.powerauth.soap.v2.PrepareActivationResponse;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthActivationException;
import io.getlime.security.powerauth.rest.api.model.request.v2.ActivationCreateRequest;
import io.getlime.security.powerauth.rest.api.model.response.v2.ActivationCreateResponse;
import io.getlime.security.powerauth.soap.spring.client.PowerAuthServiceClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Service implementing activation functionality.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>2.0</li>
 *     <li>2.1</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@Service("activationServiceV2")
public class ActivationService {

    private PowerAuthServiceClient powerAuthClient;

    private static final Logger logger = LoggerFactory.getLogger(ActivationService.class);

    @Autowired
    public void setPowerAuthClient(PowerAuthServiceClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    /**
     * Create activation.
     * @param request Create activation request.
     * @return Create activation response.
     * @throws PowerAuthActivationException In case create activation fails.
     */
    public ActivationCreateResponse createActivation(ActivationCreateRequest request) throws PowerAuthActivationException {
        try {
            String activationIDShort = request.getActivationIdShort();
            String activationNonce = request.getActivationNonce();
            String cDevicePublicKey = request.getEncryptedDevicePublicKey();
            String activationName = request.getActivationName();
            String extras = request.getExtras();
            String applicationKey = request.getApplicationKey();
            String applicationSignature = request.getApplicationSignature();
            String clientEphemeralKey = request.getEphemeralPublicKey();

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

            return response;
        } catch (Exception ex) {
            logger.warn("Creating PowerAuth activation failed", ex);
            throw new PowerAuthActivationException();
        }
    }

}
