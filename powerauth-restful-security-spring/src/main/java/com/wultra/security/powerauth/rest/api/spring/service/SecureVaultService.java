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
package com.wultra.security.powerauth.rest.api.spring.service;

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.model.enumeration.SignatureType;
import com.wultra.security.powerauth.client.model.request.VaultUnlockRequest;
import com.wultra.security.powerauth.client.model.response.VaultUnlockResponse;
import com.wultra.security.powerauth.http.PowerAuthHttpBody;
import com.wultra.security.powerauth.http.PowerAuthSignatureHttpHeader;
import com.wultra.security.powerauth.rest.api.model.request.EciesEncryptedRequest;
import com.wultra.security.powerauth.rest.api.model.response.EciesEncryptedResponse;
import com.wultra.security.powerauth.rest.api.spring.converter.SignatureTypeConverter;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthSecureVaultException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthSignatureInvalidException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthSignatureTypeInvalidException;
import com.wultra.security.powerauth.rest.api.spring.provider.PowerAuthAuthenticationProvider;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Base64;

/**
 * Service implementing secure vault functionality.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@Service("secureVaultServiceV3")
public class SecureVaultService {

    private static final Logger logger = LoggerFactory.getLogger(SecureVaultService.class);

    private final PowerAuthClient powerAuthClient;
    private final PowerAuthAuthenticationProvider authenticationProvider;
    private final HttpCustomizationService httpCustomizationService;

    /**
     * Service constructor.
     * @param powerAuthClient PowerAuth client.
     * @param authenticationProvider Authentication provider.
     * @param httpCustomizationService HTTP customization service.
     */
    @Autowired
    public SecureVaultService(PowerAuthClient powerAuthClient, PowerAuthAuthenticationProvider authenticationProvider, HttpCustomizationService httpCustomizationService) {
        this.powerAuthClient = powerAuthClient;
        this.authenticationProvider = authenticationProvider;
        this.httpCustomizationService = httpCustomizationService;
    }

    /**
     * Unlock secure vault.
     * @param header PowerAuth signature HTTP header.
     * @param request ECIES encrypted vault unlock request.
     * @param httpServletRequest HTTP servlet request.
     * @return ECIES encrypted vault unlock response.
     * @throws PowerAuthSecureVaultException In case vault unlock request fails.
     * @throws PowerAuthAuthenticationException In case authentication fails.
     */
    public EciesEncryptedResponse vaultUnlock(PowerAuthSignatureHttpHeader header,
                                              EciesEncryptedRequest request,
                                              HttpServletRequest httpServletRequest) throws PowerAuthSecureVaultException, PowerAuthAuthenticationException {
        try {
            final SignatureTypeConverter converter = new SignatureTypeConverter();

            final String activationId = header.getActivationId();
            final String applicationKey = header.getApplicationKey();
            final String signature = header.getSignature();
            final SignatureType signatureType = converter.convertFrom(header.getSignatureType());
            if (signatureType == null) {
                logger.warn("Invalid signature type: {}", header.getSignatureType());
                throw new PowerAuthSignatureTypeInvalidException();
            }
            final String signatureVersion = header.getVersion();
            final String nonce = header.getNonce();

            // Prepare data for signature to allow signature verification on PowerAuth server
            final byte[] requestBodyBytes = authenticationProvider.extractRequestBodyBytes(httpServletRequest);
            final String data = PowerAuthHttpBody.getSignatureBaseString("POST", "/pa/vault/unlock", Base64.getDecoder().decode(nonce), requestBodyBytes);

            // Verify signature and get encrypted vault encryption key from PowerAuth server
            final VaultUnlockRequest unlockRequest = new VaultUnlockRequest();
            unlockRequest.setActivationId(activationId);
            unlockRequest.setApplicationKey(applicationKey);
            unlockRequest.setSignature(signature);
            unlockRequest.setSignatureType(signatureType);
            unlockRequest.setSignatureVersion(signatureVersion);
            unlockRequest.setSignedData(data);
            unlockRequest.setTemporaryKeyId(request.getTemporaryKeyId());
            unlockRequest.setEphemeralPublicKey(request.getEphemeralPublicKey());
            unlockRequest.setEncryptedData(request.getEncryptedData());
            unlockRequest.setMac(request.getMac());
            unlockRequest.setNonce(request.getNonce());
            unlockRequest.setTimestamp(request.getTimestamp());
            final VaultUnlockResponse paResponse = powerAuthClient.unlockVault(
                    unlockRequest,
                    httpCustomizationService.getQueryParams(),
                    httpCustomizationService.getHttpHeaders()
            );

            if (!paResponse.isSignatureValid()) {
                logger.debug("Signature validation failed");
                throw new PowerAuthSignatureInvalidException();
            }

            return new EciesEncryptedResponse(
                    paResponse.getEncryptedData(),
                    paResponse.getMac(),
                    paResponse.getNonce(),
                    paResponse.getTimestamp());
        } catch (PowerAuthAuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            logger.warn("PowerAuth vault unlock failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthSecureVaultException();
        }
    }
}
