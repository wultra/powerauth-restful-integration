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

package io.getlime.security.powerauth.rest.api.spring.controller.v3;

import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.powerauth.soap.v3.CreateTokenResponse;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.request.v3.TokenRemoveRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import io.getlime.security.powerauth.rest.api.model.response.v3.TokenRemoveResponse;
import io.getlime.security.powerauth.rest.api.spring.annotation.PowerAuth;
import io.getlime.security.powerauth.rest.api.spring.converter.v3.SignatureTypeConverter;
import io.getlime.security.powerauth.soap.spring.client.PowerAuthServiceClient;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * Controller responsible for publishing services related to simple token-based authentication.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@RestController("TokenControllerV3")
@RequestMapping("/pa/v3/token")
public class TokenController {

    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(TokenController.class);

    private PowerAuthServiceClient powerAuthClient;

    @Autowired
    public void setPowerAuthClient(PowerAuthServiceClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    @RequestMapping(value = "create", method = RequestMethod.POST)
    @PowerAuth(resourceId = "/pa/token/create", signatureType = {
            PowerAuthSignatureTypes.POSSESSION,
            PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE,
            PowerAuthSignatureTypes.POSSESSION_BIOMETRY,
            PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY
    })
    public EciesEncryptedResponse createToken(@RequestBody EciesEncryptedRequest request,
                                              PowerAuthApiAuthentication authentication)
            throws PowerAuthAuthenticationException {
        try {
            if (authentication != null && authentication.getActivationId() != null) {
                if (!"3.0".equals(authentication.getVersion())) {
                    logger.warn("Endpoint does not support PowerAuth protocol version {}", authentication.getVersion());
                    throw new PowerAuthAuthenticationException();
                }

                // Fetch activation ID and signature type
                final PowerAuthSignatureTypes signatureFactors = authentication.getSignatureFactors();

                // Fetch data from the request
                final String ephemeralPublicKey = request.getEphemeralPublicKey();
                final String encryptedData = request.getEncryptedData();
                final String mac = request.getMac();

                // Prepare a signature type converter
                SignatureTypeConverter converter = new SignatureTypeConverter();

                // Get ECIES headers
                String activationId = authentication.getActivationId();
                PowerAuthSignatureHttpHeader httpHeader = (PowerAuthSignatureHttpHeader) authentication.getHttpHeader();
                String applicationKey = httpHeader.getApplicationKey();

                // Create a token
                final CreateTokenResponse token = powerAuthClient.createToken(activationId, applicationKey, ephemeralPublicKey,
                        encryptedData, mac, converter.convertFrom(signatureFactors));

                // Prepare a response
                final EciesEncryptedResponse response = new EciesEncryptedResponse();
                response.setMac(token.getMac());
                response.setEncryptedData(token.getEncryptedData());
                return response;
            } else {
                throw new PowerAuthAuthenticationException();
            }
        }  catch (PowerAuthAuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            logger.warn("Creating PowerAuth token failed.", ex);
            throw new PowerAuthAuthenticationException(ex.getMessage());
        }
    }

    @RequestMapping(value = "remove", method = RequestMethod.POST)
    @PowerAuth(resourceId = "/pa/token/remove", signatureType = {
            PowerAuthSignatureTypes.POSSESSION,
            PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE,
            PowerAuthSignatureTypes.POSSESSION_BIOMETRY,
            PowerAuthSignatureTypes.POSSESSION_KNOWLEDGE_BIOMETRY
    })
    public ObjectResponse<TokenRemoveResponse> removeToken(@RequestBody ObjectRequest<TokenRemoveRequest> request,
                                                           PowerAuthApiAuthentication authentication) throws PowerAuthAuthenticationException {
        try {
            if (authentication != null && authentication.getActivationId() != null) {

                // Fetch activation ID
                final String activationId = authentication.getActivationId();

                // Fetch token ID from the request
                final TokenRemoveRequest requestObject = request.getRequestObject();
                final String tokenId = requestObject.getTokenId();

                // Remove a token, ignore response, since the endpoint should quietly return
                powerAuthClient.removeToken(tokenId, activationId);

                // Prepare a response
                final TokenRemoveResponse responseObject = new TokenRemoveResponse();
                responseObject.setTokenId(tokenId);
                return new ObjectResponse<>(responseObject);

            } else {
                throw new PowerAuthAuthenticationException();
            }
        }  catch (PowerAuthAuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            logger.warn("Removing PowerAuth token failed.", ex);
            throw new PowerAuthAuthenticationException(ex.getMessage());
        }
    }

}
