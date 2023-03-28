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

import com.wultra.security.powerauth.client.PowerAuthClient;
import com.wultra.security.powerauth.client.v2.SignatureType;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.http.validator.InvalidPowerAuthHttpHeaderException;
import io.getlime.security.powerauth.http.validator.PowerAuthSignatureHttpHeaderValidator;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthSecureVaultException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthSignatureInvalidException;
import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthSignatureTypeInvalidException;
import io.getlime.security.powerauth.rest.api.model.request.v2.VaultUnlockRequest;
import io.getlime.security.powerauth.rest.api.model.response.v2.VaultUnlockResponse;
import io.getlime.security.powerauth.rest.api.spring.converter.v2.SignatureTypeConverter;
import io.getlime.security.powerauth.rest.api.spring.provider.PowerAuthAuthenticationProvider;
import io.getlime.security.powerauth.rest.api.spring.service.HttpCustomizationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.Base64;

/**
 * Service implementing secure vault functionality.
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
@Service("secureVaultServiceV2")
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
     * @param signatureHeader PowerAuth signature HTTP header.
     * @param request Vault unlock request.
     * @param httpServletRequest HTTP servlet request.
     * @return Vault unlock response.
     * @throws PowerAuthSecureVaultException In case vault unlock fails.
     * @throws PowerAuthAuthenticationException In case authentication fails.
     */
    public VaultUnlockResponse vaultUnlock(String signatureHeader,
                                           VaultUnlockRequest request,
                                           HttpServletRequest httpServletRequest) throws PowerAuthSecureVaultException, PowerAuthAuthenticationException {
        try {
            // Parse the header
            final PowerAuthSignatureHttpHeader header = new PowerAuthSignatureHttpHeader().fromValue(signatureHeader);

            // Validate the header
            try {
                PowerAuthSignatureHttpHeaderValidator.validate(header);
            } catch (InvalidPowerAuthHttpHeaderException ex) {
                logger.warn("Signature HTTP header validation failed, error: {}", ex.getMessage());
                logger.debug(ex.getMessage(), ex);
                throw new PowerAuthSignatureTypeInvalidException();
            }

            final SignatureTypeConverter converter = new SignatureTypeConverter();

            final String activationId = header.getActivationId();
            final String applicationKey = header.getApplicationKey();
            final String signature = header.getSignature();
            final SignatureType signatureType = converter.convertFrom(header.getSignatureType());
            if (signatureType == null) {
                logger.warn("Invalid signature type: {}", header.getSignatureType());
                throw new PowerAuthSignatureTypeInvalidException();
            }
            final String nonce = header.getNonce();

            String reason = null;
            byte[] requestBodyBytes;

            if ("2.0".equals(header.getVersion())) {
                // Version 2.0 requires null data in signature for vault unlock.
                requestBodyBytes = null;
            } else if ("2.1".equals(header.getVersion())) {
                // Version 2.1 or higher requires request data in signature (POST request body) for vault unlock.
                if (request != null) {
                    // Send vault unlock reason, in case it is available.
                    if (request.getReason() != null) {
                        reason = request.getReason();
                    }
                }

                // Use POST request body as data for signature.
                requestBodyBytes = authenticationProvider.extractRequestBodyBytes(httpServletRequest);
            } else {
                logger.warn("Invalid protocol version in secure vault: {}", header.getVersion());
                throw new PowerAuthSecureVaultException();
            }

            final String data = PowerAuthHttpBody.getSignatureBaseString("POST", "/pa/vault/unlock", Base64.getDecoder().decode(nonce), requestBodyBytes);

            final com.wultra.security.powerauth.client.v2.VaultUnlockRequest unlockRequest = new com.wultra.security.powerauth.client.v2.VaultUnlockRequest();
            unlockRequest.setActivationId(activationId);
            unlockRequest.setApplicationKey(applicationKey);
            unlockRequest.setData(data);
            unlockRequest.setSignature(signature);
            unlockRequest.setSignatureType(signatureType);
            unlockRequest.setReason(reason);
            final com.wultra.security.powerauth.client.v2.VaultUnlockResponse paResponse = powerAuthClient.v2().unlockVault(
                    unlockRequest,
                    httpCustomizationService.getQueryParams(),
                    httpCustomizationService.getHttpHeaders()
            );

            if (!paResponse.isSignatureValid()) {
                logger.debug("Signature validation failed");
                throw new PowerAuthSignatureInvalidException();
            }

            final VaultUnlockResponse response = new VaultUnlockResponse();
            response.setActivationId(paResponse.getActivationId());
            response.setEncryptedVaultEncryptionKey(paResponse.getEncryptedVaultEncryptionKey());

            return response;
        } catch (PowerAuthAuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            logger.warn("PowerAuth vault unlock failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthSecureVaultException();
        }
    }

}
