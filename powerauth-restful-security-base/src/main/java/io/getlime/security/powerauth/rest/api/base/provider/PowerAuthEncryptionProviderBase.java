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
package io.getlime.security.powerauth.rest.api.base.provider;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesDecryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEnvelopeKey;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.http.PowerAuthEncryptionHttpHeader;
import io.getlime.security.powerauth.rest.api.base.encryption.PowerAuthEciesDecryptorParameters;
import io.getlime.security.powerauth.rest.api.base.encryption.PowerAuthEciesEncryption;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthEncryptionException;
import io.getlime.security.powerauth.rest.api.base.filter.PowerAuthRequestFilterBase;
import io.getlime.security.powerauth.rest.api.base.model.PowerAuthRequestBody;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;

import javax.servlet.http.HttpServletRequest;

/**
 * Abstract class for PowerAuth encryption provider with common HTTP header parsing logic.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public abstract class PowerAuthEncryptionProviderBase {

    private ObjectMapper objectMapper = new ObjectMapper();
    private EciesFactory eciesFactory = new EciesFactory();

    /**
     * Get ECIES decryptor parameters from PowerAuth server.
     *
     * @param activationId Activation ID (only used in activation scope, in application scope use null).
     * @param applicationKey Application key.
     * @param ephemeralPublicKey Ephemeral public key for ECIES.
     * @return ECIES decryptor parameters.
     * @throws PowerAuthEncryptionException In case PowerAuth server call fails.
     */
    public abstract PowerAuthEciesDecryptorParameters getEciesDecryptorParameters(String activationId, String applicationKey, String ephemeralPublicKey) throws PowerAuthEncryptionException;

    /**
     * Decrypt HTTP request body and construct object with ECIES data. Use the requestType parameter to specify
     * the type of decrypted object.
     *
     * @param request HTTP request.
     * @param requestType Request object type.
     * @return Object with ECIES data.
     * @throws PowerAuthEncryptionException In case request decryption fails.
     */
    public <T> PowerAuthEciesEncryption<T> decryptRequest(HttpServletRequest request, Class<T> requestType) throws PowerAuthEncryptionException {
        // Only POST HTTP method is supported for ECIES
        if (!"POST".equals(request.getMethod())) {
            throw new PowerAuthEncryptionException("Invalid HTTP request");
        }
        // Construct ECIES encryption object from HTTP header
        final PowerAuthEciesEncryption<T> eciesEncryption = new PowerAuthEciesEncryption<>(request.getHeader(PowerAuthEncryptionHttpHeader.HEADER_NAME));

        try {
            // Parse ECIES cryptogram from request body
            PowerAuthRequestBody requestBody = ((PowerAuthRequestBody) request.getAttribute(PowerAuthRequestFilterBase.POWERAUTH_REQUEST_BODY));
            byte[] requestBodyBytes = requestBody.getRequestBytes();
            if (requestBodyBytes == null || requestBodyBytes.length == 0) {
                throw new PowerAuthEncryptionException("Invalid HTTP request");
            }
            final EciesEncryptedRequest eciesRequest = objectMapper.readValue(requestBodyBytes, EciesEncryptedRequest.class);

            // Prepare ephemeral public key
            String ephemeralPublicKey = eciesRequest.getEphemeralPublicKey();
            final byte[] ephemeralPublicKeyBytes = BaseEncoding.base64().decode(eciesRequest.getEphemeralPublicKey());
            final byte[] encryptedDataBytes = BaseEncoding.base64().decode(eciesRequest.getEncryptedData());
            final byte[] macBytes = BaseEncoding.base64().decode(eciesRequest.getMac());

            // Obtain ECIES decryptor parameters from PowerAuth server
            final PowerAuthEciesDecryptorParameters decryptorParameters = getEciesDecryptorParameters(eciesEncryption.getActivationId(),
                    eciesEncryption.getApplicationKey(), ephemeralPublicKey);

            // Prepare envelope key and sharedInfo2 parameter for decryptor
            final byte[] secretKey = BaseEncoding.base64().decode(decryptorParameters.getSecretKey());
            final EciesEnvelopeKey envelopeKey = new EciesEnvelopeKey(secretKey, ephemeralPublicKeyBytes);
            final byte[] sharedInfo2 = BaseEncoding.base64().decode(decryptorParameters.getSharedInfo2());

            // Construct decryptor and set it to the request for later encryption of response
            final EciesDecryptor eciesDecryptor = eciesFactory.getEciesDecryptor(envelopeKey, sharedInfo2);
            eciesEncryption.setEciesDecryptor(eciesDecryptor);

            // Decrypt request data
            EciesCryptogram cryptogram = new EciesCryptogram(ephemeralPublicKeyBytes, macBytes, encryptedDataBytes);
            byte[] decryptedData = eciesDecryptor.decryptRequest(cryptogram);
            eciesEncryption.setEncryptedRequest(encryptedDataBytes);
            eciesEncryption.setDecryptedRequest(decryptedData);
            eciesEncryption.setRequestObject(objectMapper.readValue(decryptedData, requestType));
        } catch (Exception ex) {
            ex.printStackTrace();
            throw new PowerAuthEncryptionException("Invalid HTTP request");
        }
        return eciesEncryption;
    }

    /**
     * Encrypt response using ECIES.
     * @param responseObject Response object which should be encrypted.
     * @param eciesEncryption PowerAuth encryption object.
     * @return ECIES encrypted response.
     */
    public EciesEncryptedResponse encryptResponse(Object responseObject, PowerAuthEciesEncryption eciesEncryption) {
        try {
            byte[] responseData = objectMapper.writeValueAsBytes(responseObject);
            // Encrypt response using decryptor and return ECIES cryptogram
            EciesCryptogram cryptogram = eciesEncryption.getEciesDecryptor().encryptResponse(responseData);
            String encryptedDataBase64 = BaseEncoding.base64().encode(cryptogram.getEncryptedData());
            String macBase64 = BaseEncoding.base64().encode(cryptogram.getMac());
            return new EciesEncryptedResponse(encryptedDataBase64, macBase64);
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }

}
