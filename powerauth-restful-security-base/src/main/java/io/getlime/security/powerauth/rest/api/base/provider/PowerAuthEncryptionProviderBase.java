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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesDecryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEnvelopeKey;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesScope;
import io.getlime.security.powerauth.http.PowerAuthEncryptionHttpHeader;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.http.validator.InvalidPowerAuthHttpHeaderException;
import io.getlime.security.powerauth.http.validator.PowerAuthEncryptionHttpHeaderValidator;
import io.getlime.security.powerauth.http.validator.PowerAuthSignatureHttpHeaderValidator;
import io.getlime.security.powerauth.rest.api.base.encryption.EciesEncryptionContext;
import io.getlime.security.powerauth.rest.api.base.encryption.PowerAuthEciesDecryptorParameters;
import io.getlime.security.powerauth.rest.api.base.encryption.PowerAuthEciesEncryption;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthEncryptionException;
import io.getlime.security.powerauth.rest.api.base.model.PowerAuthRequestBody;
import io.getlime.security.powerauth.rest.api.base.model.PowerAuthRequestObjects;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * Abstract class for PowerAuth encryption provider with common HTTP header parsing logic.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public abstract class PowerAuthEncryptionProviderBase {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final EciesFactory eciesFactory = new EciesFactory();

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
     * @param <T> Generic request object type.
     * @param request HTTP request.
     * @param requestType Class of request object.
     * @param eciesScope ECIES scope.
     * @return Object with ECIES data.
     * @throws PowerAuthEncryptionException In case request decryption fails.
     */
    public <T> PowerAuthEciesEncryption<T> decryptRequest(HttpServletRequest request, Class<T> requestType, EciesScope eciesScope) throws PowerAuthEncryptionException {
        // Only POST HTTP method is supported for ECIES
        if (!"POST".equals(request.getMethod())) {
            throw new PowerAuthEncryptionException("Invalid HTTP request");
        }

        // Resolve either signature or encryption HTTP header for ECIES
        EciesEncryptionContext encryptionContext = extractEciesEncryptionContext(request);

        // Construct ECIES encryption object from HTTP header
        final PowerAuthEciesEncryption<T> eciesEncryption = new PowerAuthEciesEncryption<>(encryptionContext);

        // Save ECIES scope in context
        eciesEncryption.getContext().setEciesScope(eciesScope);

        try {
            // Parse ECIES cryptogram from request body
            PowerAuthRequestBody requestBody = ((PowerAuthRequestBody) request.getAttribute(PowerAuthRequestObjects.REQUEST_BODY));
            if (requestBody == null) {
                throw new PowerAuthEncryptionException("The X-PowerAuth-Request-Body request attribute is missing, register the PowerAuthRequestFilter to fix this error");
            }
            byte[] requestBodyBytes = requestBody.getRequestBytes();
            if (requestBodyBytes == null || requestBodyBytes.length == 0) {
                throw new PowerAuthEncryptionException("Invalid HTTP request");
            }
            final EciesEncryptedRequest eciesRequest = objectMapper.readValue(requestBodyBytes, EciesEncryptedRequest.class);
            if (eciesRequest == null) {
                throw new PowerAuthEncryptionException("Invalid ECIES request data");
            }

            // Prepare ephemeral public key
            final String ephemeralPublicKey = eciesRequest.getEphemeralPublicKey();
            final String encryptedData = eciesRequest.getEncryptedData();
            final String mac = eciesRequest.getMac();
            final String nonce = eciesRequest.getNonce();

            // Verify ECIES request data. Nonce is required for protocol 3.1+
            if (ephemeralPublicKey == null || encryptedData == null || mac == null) {
                throw new PowerAuthEncryptionException("Invalid ECIES request data");
            }
            if (nonce == null && !"3.0".equals(encryptionContext.getVersion())) {
                throw new PowerAuthEncryptionException("Missing nonce in ECIES request data");
            }

            final byte[] ephemeralPublicKeyBytes = BaseEncoding.base64().decode(ephemeralPublicKey);
            final byte[] encryptedDataBytes = BaseEncoding.base64().decode(encryptedData);
            final byte[] macBytes = BaseEncoding.base64().decode(mac);
            final byte[] nonceBytes = nonce != null ? BaseEncoding.base64().decode(nonce) : null;

            final String applicationKey = eciesEncryption.getContext().getApplicationKey();
            final PowerAuthEciesDecryptorParameters decryptorParameters;
            // Obtain ECIES decryptor parameters from PowerAuth server
            switch (eciesScope) {
                case ACTIVATION_SCOPE:
                    final String activationId = eciesEncryption.getContext().getActivationId();
                    if (activationId == null) {
                        throw new PowerAuthEncryptionException("Activation ID is required in ECIES activation scope");
                    }
                    decryptorParameters = getEciesDecryptorParameters(activationId, applicationKey, ephemeralPublicKey);
                    break;
                case APPLICATION_SCOPE:
                    decryptorParameters = getEciesDecryptorParameters(null, applicationKey, ephemeralPublicKey);
                    break;
                default:
                    throw new PowerAuthEncryptionException("Unsupported ECIES scope: " + eciesScope);
            }

            // Prepare envelope key and sharedInfo2 parameter for decryptor
            final byte[] secretKey = BaseEncoding.base64().decode(decryptorParameters.getSecretKey());
            final EciesEnvelopeKey envelopeKey = new EciesEnvelopeKey(secretKey, ephemeralPublicKeyBytes);
            final byte[] sharedInfo2 = BaseEncoding.base64().decode(decryptorParameters.getSharedInfo2());

            // Construct decryptor and set it to the request for later encryption of response
            final EciesDecryptor eciesDecryptor = eciesFactory.getEciesDecryptor(envelopeKey, sharedInfo2);
            eciesEncryption.setEciesDecryptor(eciesDecryptor);

            // Decrypt request data
            EciesCryptogram cryptogram = new EciesCryptogram(ephemeralPublicKeyBytes, macBytes, encryptedDataBytes, nonceBytes);
            byte[] decryptedData = eciesDecryptor.decryptRequest(cryptogram);
            eciesEncryption.setEncryptedRequest(encryptedDataBytes);
            eciesEncryption.setDecryptedRequest(decryptedData);
            // Set the request object only in case when request data is sent
            if (decryptedData.length != 0) {
                eciesEncryption.setRequestObject(deserializeRequestData(decryptedData, requestType));
            }

            // Set encryption object in HTTP servlet request
            request.setAttribute(PowerAuthRequestObjects.ENCRYPTION_OBJECT, eciesEncryption);
        } catch (Exception ex) {
            throw new PowerAuthEncryptionException("Invalid request");
        }
        return eciesEncryption;
    }

    /**
     * Encrypt response using ECIES.
     *
     * @param responseObject Response object which should be encrypted.
     * @param eciesEncryption PowerAuth encryption object.
     * @return ECIES encrypted response.
     */
    public EciesEncryptedResponse encryptResponse(Object responseObject, PowerAuthEciesEncryption eciesEncryption) {
        try {
            byte[] responseData = serializeResponseData(responseObject);
            // Encrypt response using decryptor and return ECIES cryptogram
            EciesCryptogram cryptogram = eciesEncryption.getEciesDecryptor().encryptResponse(responseData);
            String encryptedDataBase64 = BaseEncoding.base64().encode(cryptogram.getEncryptedData());
            String macBase64 = BaseEncoding.base64().encode(cryptogram.getMac());
            return new EciesEncryptedResponse(encryptedDataBase64, macBase64);
        } catch (Exception ex) {
            return null;
        }
    }

    /**
     * Convert byte[] request data to Object with given type.
     *
     * @param requestData Raw request data.
     * @param requestType Class specifying request type.
     * @param <T> Type of request object.
     * @return Request object.
     * @throws IOException In case request object could not be deserialized.
     */
    @SuppressWarnings("unchecked")
    private <T> T deserializeRequestData(byte[] requestData, Class<T> requestType) throws IOException {
        if (requestType.equals(byte[].class)) {
            // Raw data without deserialization from JSON
            return (T) requestData;
        } else {
            // Object is deserialized from JSON based on request type
            return objectMapper.readValue(requestData, requestType);
        }
    }

    /**
     * Convert response object to byte[].
     *
     * @param responseObject Response object.
     * @return Response data as byte[].
     * @throws JsonProcessingException In case JSON serialization fails.
     */
    private byte[] serializeResponseData(Object responseObject) throws JsonProcessingException {
        if (responseObject.getClass().equals(byte[].class)) {
            // Raw data without serialization into JSON
            return (byte[]) responseObject;
        } else {
            // Object is serialized to JSON
            return objectMapper.writeValueAsBytes(responseObject);
        }
    }

    /**
     * Extract context required for ECIES encryption from either encryption or signature HTTP header.
     *
     * @param request HTTP servlet request.
     * @return Context for ECIES encryption.
     * @throws PowerAuthEncryptionException Thrown when HTTP header with ECIES data is invalid.
     */
    private EciesEncryptionContext extractEciesEncryptionContext(HttpServletRequest request) throws PowerAuthEncryptionException {
        final String encryptionHttpHeader = request.getHeader(PowerAuthEncryptionHttpHeader.HEADER_NAME);
        final String signatureHttpHeader = request.getHeader(PowerAuthSignatureHttpHeader.HEADER_NAME);

        // Check that at least one PowerAuth HTTP header with parameters for ECIES is present
        if (encryptionHttpHeader == null && signatureHttpHeader == null) {
            throw new PowerAuthEncryptionException("POWER_AUTH_ENCRYPTION_INVALID_HEADER");
        }

        // In case the PowerAuth signature HTTP header is present, use it for ECIES
        if (signatureHttpHeader != null) {
            // Parse signature HTTP header
            PowerAuthSignatureHttpHeader header = new PowerAuthSignatureHttpHeader().fromValue(signatureHttpHeader);

            // Validate the signature HTTP header
            try {
                PowerAuthSignatureHttpHeaderValidator.validate(header);
            } catch (InvalidPowerAuthHttpHeaderException e) {
                throw new PowerAuthEncryptionException(e.getMessage());
            }

            // Construct encryption parameters object
            String applicationKey = header.getApplicationKey();
            String activationId = header.getActivationId();
            String version = header.getVersion();
            return new EciesEncryptionContext(applicationKey, activationId, version, header);
        } else {
            // Parse encryption HTTP header
            PowerAuthEncryptionHttpHeader header = new PowerAuthEncryptionHttpHeader().fromValue(encryptionHttpHeader);

            // Validate the encryption HTTP header
            try {
                PowerAuthEncryptionHttpHeaderValidator.validate(header);
            } catch (InvalidPowerAuthHttpHeaderException e) {
                throw new PowerAuthEncryptionException(e.getMessage());
            }

            // Construct encryption parameters object
            String applicationKey = header.getApplicationKey();
            String activationId = header.getActivationId();
            String version = header.getVersion();
            return new EciesEncryptionContext(applicationKey, activationId, version, header);
        }
    }

}
