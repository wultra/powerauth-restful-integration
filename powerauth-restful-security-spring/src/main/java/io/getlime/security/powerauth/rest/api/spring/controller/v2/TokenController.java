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
import io.getlime.powerauth.soap.v2.CreateTokenResponse;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.http.validator.InvalidPowerAuthHttpHeaderException;
import io.getlime.security.powerauth.http.validator.PowerAuthSignatureHttpHeaderValidator;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthSecureVaultException;
import io.getlime.security.powerauth.rest.api.model.request.TokenRemoveRequest;
import io.getlime.security.powerauth.rest.api.model.request.TokenCreateRequest;
import io.getlime.security.powerauth.rest.api.model.response.TokenRemoveResponse;
import io.getlime.security.powerauth.rest.api.model.response.TokenCreateResponse;
import io.getlime.security.powerauth.rest.api.spring.annotation.PowerAuth;
import io.getlime.security.powerauth.rest.api.spring.converter.v2.SignatureTypeConverter;
import io.getlime.security.powerauth.soap.spring.client.PowerAuthServiceClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Controller responsible for publishing services related to simple token-based authentication.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@RestController
@RequestMapping("/pa/token")
public class TokenController {

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
    public ObjectResponse<TokenCreateResponse> createToken(
            @RequestHeader(value = PowerAuthSignatureHttpHeader.HEADER_NAME, defaultValue = "unknown") String signatureHeader,
            @RequestBody ObjectRequest<TokenCreateRequest> request, PowerAuthApiAuthentication authentication) throws PowerAuthAuthenticationException {
        try {
            if (authentication != null && authentication.getActivationId() != null) {
                // Parse the header
                PowerAuthSignatureHttpHeader header = new PowerAuthSignatureHttpHeader().fromValue(signatureHeader);

                // Validate the header
                try {
                    PowerAuthSignatureHttpHeaderValidator.validate(header);
                } catch (InvalidPowerAuthHttpHeaderException e) {
                    throw new PowerAuthAuthenticationException(e.getMessage());
                }

                if (!"2.0".equals(header.getVersion()) && !"2.1".equals(header.getVersion())) {
                    Logger.getLogger(this.getClass().getName()).log(Level.SEVERE, "Endpoint does not support PowerAuth protocol version {}", header.getVersion());
                    throw new PowerAuthSecureVaultException();
                }

                // Fetch activation ID and signature type
                final String activationId = authentication.getActivationId();
                final PowerAuthSignatureTypes signatureFactors = authentication.getSignatureFactors();

                // Fetch data from the request
                final TokenCreateRequest requestObject = request.getRequestObject();
                final String ephemeralPublicKey = requestObject.getEphemeralPublicKey();

                // Prepare a signature type converter
                SignatureTypeConverter converter = new SignatureTypeConverter();

                // Create a token
                final CreateTokenResponse token = powerAuthClient.v2().createToken(activationId, ephemeralPublicKey, converter.convertFrom(signatureFactors));

                // Prepare a response
                final TokenCreateResponse responseObject = new TokenCreateResponse();
                responseObject.setMac(token.getMac());
                responseObject.setEncryptedData(token.getEncryptedData());
                return new ObjectResponse<>(responseObject);
            } else {
                throw new PowerAuthAuthenticationException();
            }
        }  catch (PowerAuthAuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            Logger.getLogger(this.getClass().getName()).log(Level.WARNING, "Creating PowerAuth token failed.", ex);
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
    public ObjectResponse<TokenRemoveResponse> removeToken(@RequestBody ObjectRequest<TokenRemoveRequest> request, PowerAuthApiAuthentication authentication) throws PowerAuthAuthenticationException {
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
                responseObject.setTokenId(requestObject.getTokenId());
                return new ObjectResponse<>(responseObject);

            } else {
                throw new PowerAuthAuthenticationException();
            }
        }  catch (PowerAuthAuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            Logger.getLogger(this.getClass().getName()).log(Level.WARNING, "Removing PowerAuth token failed.", ex);
            throw new PowerAuthAuthenticationException(ex.getMessage());
        }
    }

}
