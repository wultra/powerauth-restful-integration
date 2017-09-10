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
package io.getlime.security.powerauth.rest.api.spring.controller;

import com.google.common.io.BaseEncoding;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.powerauth.soap.SignatureType;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthHttpHeader;
import io.getlime.security.powerauth.http.validator.InvalidPowerAuthHttpHeaderException;
import io.getlime.security.powerauth.http.validator.PowerAuthHttpHeaderValidator;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthSecureVaultException;
import io.getlime.security.powerauth.rest.api.model.response.VaultUnlockResponse;
import io.getlime.security.powerauth.soap.spring.client.PowerAuthServiceClient;
import io.getlime.security.powerauth.rest.api.spring.converter.SignatureTypeConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Controller implementing secure vault related end-points from the
 * PowerAuth Standard API.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Controller
@RequestMapping(value = "/pa/vault")
public class SecureVaultController {

    private PowerAuthServiceClient powerAuthClient;

    @Autowired
    public void setPowerAuthClient(PowerAuthServiceClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    /**
     * Request the vault unlock key.
     * @param signatureHeader PowerAuth signature HTTP header.
     * @return PowerAuth RESTful response with {@link VaultUnlockResponse} payload.
     * @throws PowerAuthAuthenticationException In case authentication fails.
     */
    @RequestMapping(value = "unlock", method = RequestMethod.POST)
    public @ResponseBody ObjectResponse<VaultUnlockResponse> unlockVault(
            @RequestHeader(value = PowerAuthHttpHeader.HEADER_NAME, defaultValue = "unknown") String signatureHeader)
            throws PowerAuthAuthenticationException, PowerAuthSecureVaultException {

        try {
            PowerAuthHttpHeader header = PowerAuthHttpHeader.fromValue(signatureHeader);

            try {
                PowerAuthHttpHeaderValidator.validate(header);
            } catch (InvalidPowerAuthHttpHeaderException e) {
                throw new PowerAuthAuthenticationException(e.getMessage());
            }

            SignatureTypeConverter converter = new SignatureTypeConverter();

            String activationId = header.getActivationId();
            String applicationId = header.getApplicationKey();
            String signature = header.getSignature();
            SignatureType signatureType = converter.convertFrom(header.getSignatureType());
            String nonce = header.getNonce();

            String data = PowerAuthHttpBody.getSignatureBaseString("POST", "/pa/vault/unlock", BaseEncoding.base64().decode(nonce), null);

            io.getlime.powerauth.soap.VaultUnlockResponse soapResponse = powerAuthClient.unlockVault(activationId, applicationId, data, signature, signatureType);

            if (!soapResponse.isSignatureValid()) {
                throw new PowerAuthAuthenticationException();
            }

            VaultUnlockResponse response = new VaultUnlockResponse();
            response.setActivationId(soapResponse.getActivationId());
            response.setEncryptedVaultEncryptionKey(soapResponse.getEncryptedVaultEncryptionKey());

            return new ObjectResponse<>(response);
        } catch (Exception ex) {
            if (PowerAuthAuthenticationException.class.equals(ex.getClass())) {
                throw ex;
            } else {
                throw new PowerAuthSecureVaultException();
            }
        }
    }

}
