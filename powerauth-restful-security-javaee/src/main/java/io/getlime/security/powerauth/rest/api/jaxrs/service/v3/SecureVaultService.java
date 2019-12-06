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
package io.getlime.security.powerauth.rest.api.jaxrs.service.v3;

import com.google.common.io.BaseEncoding;
import io.getlime.powerauth.soap.v3.PowerAuthPortV3ServiceStub;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthSecureVaultException;
import io.getlime.security.powerauth.rest.api.jaxrs.converter.v3.SignatureTypeConverter;
import io.getlime.security.powerauth.rest.api.jaxrs.provider.PowerAuthAuthenticationProvider;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
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
 *     <li>3.0</li>
 * </ul>
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
@Stateless(name = "SecureVaultServiceV3")
public class SecureVaultService {

    @Inject
    private PowerAuthServiceClient powerAuthClient;

    @Inject
    private PowerAuthAuthenticationProvider authenticationProvider;

    private static final Logger logger = LoggerFactory.getLogger(SecureVaultService.class);

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
            SignatureTypeConverter converter = new SignatureTypeConverter();

            String activationId = header.getActivationId();
            String applicationKey = header.getApplicationKey();
            String signature = header.getSignature();
            PowerAuthPortV3ServiceStub.SignatureType signatureType = converter.convertFrom(header.getSignatureType());
            String signatureVersion = header.getVersion();
            String nonce = header.getNonce();

            // Fetch data from the request
            final String ephemeralPublicKey = request.getEphemeralPublicKey();
            final String encryptedData = request.getEncryptedData();
            final String mac = request.getMac();
            final String eciesNonce = request.getNonce();

            // Prepare data for signature to allow signature verification on PowerAuth server
            byte[] requestBodyBytes = authenticationProvider.extractRequestBodyBytes(httpServletRequest);
            String data = PowerAuthHttpBody.getSignatureBaseString("POST", "/pa/vault/unlock", BaseEncoding.base64().decode(nonce), requestBodyBytes);

            // Verify signature and get encrypted vault encryption key from PowerAuth server
            PowerAuthPortV3ServiceStub.VaultUnlockResponse soapResponse = powerAuthClient.unlockVault(activationId, applicationKey, signature,
                    signatureType, signatureVersion, data, ephemeralPublicKey, encryptedData, mac, eciesNonce);

            if (!soapResponse.getSignatureValid()) {
                throw new PowerAuthAuthenticationException();
            }

            return new EciesEncryptedResponse(soapResponse.getEncryptedData(), soapResponse.getMac());
        } catch (PowerAuthAuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            logger.warn("PowerAuth vault unlock failed", ex);
            throw new PowerAuthSecureVaultException();
        }
    }
}
