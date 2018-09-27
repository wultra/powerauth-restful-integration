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

package io.getlime.security.powerauth.rest.api.jaxrs.controller.v2;

import com.google.common.io.BaseEncoding;
import io.getlime.core.rest.model.base.request.ObjectRequest;
import io.getlime.core.rest.model.base.response.ObjectResponse;
import io.getlime.powerauth.soap.v2.PowerAuthPortV2ServiceStub;
import io.getlime.security.powerauth.http.PowerAuthHttpBody;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.http.validator.InvalidPowerAuthHttpHeaderException;
import io.getlime.security.powerauth.http.validator.PowerAuthSignatureHttpHeaderValidator;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthSecureVaultException;
import io.getlime.security.powerauth.rest.api.base.filter.PowerAuthRequestFilterBase;
import io.getlime.security.powerauth.rest.api.jaxrs.converter.v2.SignatureTypeConverter;
import io.getlime.security.powerauth.rest.api.model.request.v2.VaultUnlockRequest;
import io.getlime.security.powerauth.rest.api.model.response.v2.VaultUnlockResponse;
import io.getlime.security.powerauth.soap.axis.client.PowerAuthServiceClient;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

/**
 * Controller implementing secure vault related end-points from the
 * PowerAuth Standard API.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@Path("pa/vault")
@Produces(MediaType.APPLICATION_JSON)
public class SecureVaultController {

    @Inject
    private PowerAuthServiceClient powerAuthClient;

    /**
     * Request the vault unlock key.
     * @param signatureHeader PowerAuth signature HTTP header.
     * @param request Vault unlock request data.
     * @param httpServletRequest HTTP servlet request.
     * @return PowerAuth RESTful response with {@link VaultUnlockResponse} payload.
     * @throws PowerAuthAuthenticationException In case authentication fails.
     * @throws PowerAuthSecureVaultException In case unlocking the vault fails.
     */
    @POST
    @Consumes({MediaType.APPLICATION_JSON})
    @Produces({MediaType.APPLICATION_JSON})
    @Path("unlock")
    public ObjectResponse<VaultUnlockResponse> unlockVault(@HeaderParam(PowerAuthSignatureHttpHeader.HEADER_NAME) String signatureHeader,
                                                           ObjectRequest<VaultUnlockRequest> request,
                                                           @Context HttpServletRequest httpServletRequest) throws PowerAuthAuthenticationException, PowerAuthSecureVaultException {
        try {
            PowerAuthSignatureHttpHeader header = new PowerAuthSignatureHttpHeader().fromValue(signatureHeader);

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
            String nonce = header.getNonce();

            String reason = null;

            if (request != null) {
                VaultUnlockRequest vaultUnlockRequest = request.getRequestObject();
                if (vaultUnlockRequest != null && vaultUnlockRequest.getReason() != null) {
                    reason = vaultUnlockRequest.getReason();
                }
            }

            String requestBodyString = ((String) httpServletRequest.getAttribute(PowerAuthRequestFilterBase.POWERAUTH_SIGNATURE_BASE_STRING));
            byte[] requestBodyBytes = requestBodyString == null ? null : BaseEncoding.base64().decode(requestBodyString);

            String data = PowerAuthHttpBody.getSignatureBaseString("POST", "/pa/vault/unlock", BaseEncoding.base64().decode(nonce), requestBodyBytes);

            PowerAuthPortV2ServiceStub.VaultUnlockResponse soapResponse = powerAuthClient.v2().unlockVault(activationId, applicationId, data, signature, signatureType, reason);

            if (!soapResponse.getSignatureValid()) {
                throw new PowerAuthAuthenticationException();
            }

            VaultUnlockResponse response = new VaultUnlockResponse();
            response.setActivationId(soapResponse.getActivationId());
            response.setEncryptedVaultEncryptionKey(soapResponse.getEncryptedVaultEncryptionKey());

            return new ObjectResponse<>(response);
        } catch (PowerAuthAuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new PowerAuthSecureVaultException();
        }
    }

}
