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
package io.getlime.security.powerauth.rest.api.jaxrs.service.v2;

import com.google.common.io.BaseEncoding;
import io.getlime.powerauth.soap.v2.PowerAuthPortV2ServiceStub;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.http.validator.InvalidPowerAuthHttpHeaderException;
import io.getlime.security.powerauth.http.validator.PowerAuthSignatureHttpHeaderValidator;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthSecureVaultException;
import io.getlime.security.powerauth.rest.api.jaxrs.converter.v2.SignatureTypeConverter;
import io.getlime.security.powerauth.rest.api.jaxrs.provider.PowerAuthAuthenticationProvider;
import io.getlime.security.powerauth.rest.api.model.request.v2.VaultUnlockRequest;
import io.getlime.security.powerauth.rest.api.model.response.v2.VaultUnlockResponse;
import io.getlime.security.powerauth.soap.axis.client.PowerAuthServiceClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ejb.Stateless;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

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
@Stateless(name = "SecureVaultServiceV2")
public class SecureVaultService {

    private static final Logger logger = LoggerFactory.getLogger(SecureVaultService.class);

    @Inject
    private PowerAuthServiceClient powerAuthClient;

    @Inject
    private PowerAuthAuthenticationProvider authenticationProvider;

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
            PowerAuthSignatureHttpHeader header = new PowerAuthSignatureHttpHeader().fromValue(signatureHeader);

            // Validate the header
            try {
                PowerAuthSignatureHttpHeaderValidator.validate(header);
            } catch (InvalidPowerAuthHttpHeaderException e) {
                throw new PowerAuthAuthenticationException(e.getMessage());
            }

            SignatureTypeConverter converter = new SignatureTypeConverter();

            String activationId = header.getActivationId();
            String applicationId = header.getApplicationKey();
            String signature = header.getSignature();
            PowerAuthPortV2ServiceStub.SignatureType signatureType = converter.convertFrom(header.getSignatureType());
            if (signatureType == null) {
                throw new PowerAuthAuthenticationException("POWER_AUTH_SIGNATURE_TYPE_INVALID");
            }

            String nonce = header.getNonce();

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
                throw new PowerAuthSecureVaultException();
            }

            String data = PowerAuthHttpBody.getSignatureBaseString("POST", "/pa/vault/unlock", BaseEncoding.base64().decode(nonce), requestBodyBytes);

            PowerAuthPortV2ServiceStub.VaultUnlockResponse soapResponse = powerAuthClient.v2().unlockVault(activationId, applicationId, data, signature, signatureType, reason);

            if (!soapResponse.getSignatureValid()) {
                throw new PowerAuthAuthenticationException();
            }

            VaultUnlockResponse response = new VaultUnlockResponse();
            response.setActivationId(soapResponse.getActivationId());
            response.setEncryptedVaultEncryptionKey(soapResponse.getEncryptedVaultEncryptionKey());

            return response;
        } catch (PowerAuthAuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            logger.warn("PowerAuth vault unlock failed", ex);
            throw new PowerAuthSecureVaultException();
        }
    }

}
