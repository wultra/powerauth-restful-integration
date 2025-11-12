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
package com.wultra.security.powerauth.rest.api.spring.service.v3;

import com.wultra.security.powerauth.client.v3.PowerAuthClient;
import com.wultra.security.powerauth.client.model.enumeration.v3.SignatureType;
import com.wultra.security.powerauth.client.model.request.v3.VaultUnlockRequest;
import com.wultra.security.powerauth.client.model.response.v3.VaultUnlockResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedResponse;
import com.wultra.security.powerauth.http.PowerAuthHttpBody;
import com.wultra.security.powerauth.http.PowerAuthAuthorizationHttpHeader;
import com.wultra.security.powerauth.rest.api.spring.converter.SignatureTypeConverter;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthSecureVaultException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthCodeInvalidException;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthCodeTypeInvalidException;
import com.wultra.security.powerauth.rest.api.spring.provider.PowerAuthAuthenticationProvider;
import com.wultra.security.powerauth.rest.api.spring.service.HttpCustomizationService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Base64;

/**
 * Service implementing secure vault functionality.
 *
 * <p><b>PowerAuth protocol versions:</b>
 * <ul>
 *     <li>3.0</li>
 *     <li>3.1</li>
 *     <li>3.2</li>
 *     <li>3.3</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@Service("secureVaultServiceV3")
@AllArgsConstructor
@Slf4j
public class SecureVaultService {

    private final PowerAuthClient powerAuthClient;
    private final PowerAuthAuthenticationProvider authenticationProvider;
    private final HttpCustomizationService httpCustomizationService;
    private final SignatureTypeConverter converter = new SignatureTypeConverter();

    /**
     * Unlock secure vault.
     * @param header PowerAuth signature HTTP header.
     * @param request ECIES encrypted vault unlock request.
     * @param httpServletRequest HTTP servlet request.
     * @return ECIES encrypted vault unlock response.
     * @throws PowerAuthSecureVaultException In case vault unlock request fails.
     * @throws PowerAuthAuthenticationException In case authentication fails.
     */
    public EciesEncryptedResponse vaultUnlock(PowerAuthAuthorizationHttpHeader header,
                                              EciesEncryptedRequest request,
                                              HttpServletRequest httpServletRequest) throws PowerAuthSecureVaultException, PowerAuthAuthenticationException {
        try {

            final String activationId = header.getActivationId();
            final String applicationKey = header.getApplicationKey();
            final String authCode = header.getAuthCode();
            final SignatureType signatureType = converter.convertFrom(header.getAuthCodeType());
            if (signatureType == null) {
                logger.warn("Invalid signature type: {}", header.getAuthCodeType());
                throw new PowerAuthCodeTypeInvalidException();
            }
            final String signatureVersion = header.getVersion();
            final String nonce = header.getNonce();

            // Prepare data for signature to allow signature verification on PowerAuth server
            final byte[] requestBodyBytes = authenticationProvider.extractRequestBodyBytes(httpServletRequest);
            final String data = PowerAuthHttpBody.getAuthenticationBaseString("POST", "/pa/vault/unlock", Base64.getDecoder().decode(nonce), requestBodyBytes);

            // Verify signature and get encrypted vault encryption key from PowerAuth server
            final VaultUnlockRequest unlockRequest = new VaultUnlockRequest();
            unlockRequest.setActivationId(activationId);
            unlockRequest.setApplicationKey(applicationKey);
            unlockRequest.setSignature(authCode);
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
                throw new PowerAuthCodeInvalidException();
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
