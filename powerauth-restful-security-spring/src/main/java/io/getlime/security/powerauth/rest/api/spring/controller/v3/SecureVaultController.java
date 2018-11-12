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
import io.getlime.powerauth.soap.v3.SignatureType;
import io.getlime.powerauth.soap.v3.VaultUnlockResponse;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.http.validator.InvalidPowerAuthHttpHeaderException;
import io.getlime.security.powerauth.http.validator.PowerAuthSignatureHttpHeaderValidator;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthSecureVaultException;
import io.getlime.security.powerauth.rest.api.base.filter.PowerAuthRequestFilterBase;
import io.getlime.security.powerauth.rest.api.base.model.PowerAuthRequestBody;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import io.getlime.security.powerauth.rest.api.spring.converter.v3.SignatureTypeConverter;
import io.getlime.security.powerauth.soap.spring.client.PowerAuthServiceClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

/**
 * Controller implementing secure vault related end-points from the
 * PowerAuth Standard API.
 *
 * <h5>PowerAuth protocol versions:</h5>
 * <ul>
 *     <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@RestController("SecureVaultControllerV3")
@RequestMapping(value = "/pa/v3/vault")
public class SecureVaultController {

    private static final Logger logger = LoggerFactory.getLogger(SecureVaultController.class);

    private PowerAuthServiceClient powerAuthClient;

    @Autowired
    public void setPowerAuthClient(PowerAuthServiceClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    /**
     * Request the vault unlock key.
     *
     * @param signatureHeader PowerAuth HTTP signature header.
     * @param request Request object encrypted by ECIES.
     * @param httpServletRequest HTTP servlet request.
     * @return Response object encrypted by ECIES.
     */
    @RequestMapping(value = "unlock", method = RequestMethod.POST)
    public EciesEncryptedResponse unlockVault(
            @RequestHeader(value = PowerAuthSignatureHttpHeader.HEADER_NAME, defaultValue = "unknown") String signatureHeader,
            @RequestBody EciesEncryptedRequest request,
            HttpServletRequest httpServletRequest)
            throws PowerAuthAuthenticationException, PowerAuthSecureVaultException {

        try {
            // Parse the header
            PowerAuthSignatureHttpHeader header = new PowerAuthSignatureHttpHeader().fromValue(signatureHeader);

            // Validate the header
            try {
                PowerAuthSignatureHttpHeaderValidator.validate(header);
            } catch (InvalidPowerAuthHttpHeaderException e) {
                throw new PowerAuthAuthenticationException(e.getMessage());
            }

            if (!"3.0".equals(header.getVersion())) {
                logger.warn("Endpoint does not support PowerAuth protocol version {}", header.getVersion());
                throw new PowerAuthAuthenticationException();
            }

            SignatureTypeConverter converter = new SignatureTypeConverter();

            String activationId = header.getActivationId();
            String applicationKey = header.getApplicationKey();
            String signature = header.getSignature();
            SignatureType signatureType = converter.convertFrom(header.getSignatureType());
            String nonce = header.getNonce();

            // Fetch data from the request
            final String ephemeralPublicKey = request.getEphemeralPublicKey();
            final String encryptedData = request.getEncryptedData();
            final String mac = request.getMac();

            // Prepare data for signature to allow signature verification on PowerAuth server
            PowerAuthRequestBody requestBody = ((PowerAuthRequestBody) httpServletRequest.getAttribute(PowerAuthRequestFilterBase.POWERAUTH_REQUEST_BODY));
            byte[] requestBodyBytes = requestBody.getRequestBytes();
            String data = PowerAuthHttpBody.getSignatureBaseString("POST", "/pa/vault/unlock", BaseEncoding.base64().decode(nonce), requestBodyBytes);

            // Verify signature and get encrypted vault encryption key from PowerAuth server
            VaultUnlockResponse soapResponse = powerAuthClient.unlockVault(activationId, applicationKey, signature,
                    signatureType, data, ephemeralPublicKey, encryptedData, mac);

            if (!soapResponse.isSignatureValid()) {
                throw new PowerAuthAuthenticationException();
            }

            return new EciesEncryptedResponse(soapResponse.getEncryptedData(), soapResponse.getMac());
        } catch (Exception ex) {
            if (PowerAuthAuthenticationException.class.equals(ex.getClass())) {
                throw ex;
            } else {
                logger.warn("PowerAuth vault unlock failed.", ex);
                throw new PowerAuthSecureVaultException();
            }
        }
    }

}
