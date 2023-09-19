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
package io.getlime.security.powerauth.rest.api.spring.provider;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.TypeFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ServerEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.*;
import io.getlime.security.powerauth.crypto.lib.encryptor.model.v3.ServerEncryptorSecrets;
import io.getlime.security.powerauth.http.PowerAuthEncryptionHttpHeader;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.http.validator.InvalidPowerAuthHttpHeaderException;
import io.getlime.security.powerauth.http.validator.PowerAuthEncryptionHttpHeaderValidator;
import io.getlime.security.powerauth.http.validator.PowerAuthSignatureHttpHeaderValidator;
import io.getlime.security.powerauth.rest.api.model.request.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.EciesEncryptedResponse;
import io.getlime.security.powerauth.rest.api.spring.encryption.EncryptionContext;
import io.getlime.security.powerauth.rest.api.spring.encryption.EncryptionScope;
import io.getlime.security.powerauth.rest.api.spring.encryption.PowerAuthEncryptorParameters;
import io.getlime.security.powerauth.rest.api.spring.encryption.PowerAuthEncryptorData;
import io.getlime.security.powerauth.rest.api.spring.exception.PowerAuthEncryptionException;
import io.getlime.security.powerauth.rest.api.spring.model.PowerAuthRequestBody;
import io.getlime.security.powerauth.rest.api.spring.model.PowerAuthRequestObjects;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.IOException;
import java.lang.reflect.Type;
import java.util.Base64;

/**
 * Abstract class for PowerAuth encryption provider with common HTTP header parsing logic. The class is available for
 * protocol version 3.0 and newer.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 *
 */
public abstract class PowerAuthEncryptionProviderBase {

    private static final Logger logger = LoggerFactory.getLogger(PowerAuthEncryptionProviderBase.class);

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final EncryptorFactory encryptorFactory = new EncryptorFactory();

    /**
     * Get ECIES decryptor parameters from PowerAuth server.
     *
     * @param activationId       Activation ID (only used in activation scope, in application scope use null).
     * @param applicationKey     Application key.
     * @param ephemeralPublicKey Ephemeral public key for ECIES.
     * @param version            ECIES protocol version.
     * @param nonce              ECIES nonce.
     * @param timestamp          Timestamp for ECIES.
     * @return ECIES decryptor parameters.
     * @throws PowerAuthEncryptionException In case PowerAuth server call fails.
     */
    public abstract @Nonnull
    PowerAuthEncryptorParameters getEciesDecryptorParameters(@Nullable String activationId, @Nonnull String applicationKey, @Nonnull String ephemeralPublicKey, @Nonnull String version, String nonce, Long timestamp) throws PowerAuthEncryptionException;

    /**
     * Decrypt HTTP request body and construct object with ECIES data. Use the requestType parameter to specify
     * the type of decrypted object.
     *
     * @param request         HTTP request.
     * @param requestType     Class of request object.
     * @param encryptionScope Encryption scope.
     * @throws PowerAuthEncryptionException In case request decryption fails.
     */
    public void decryptRequest(@Nonnull HttpServletRequest request, @Nonnull Type requestType, @Nonnull EncryptionScope encryptionScope) throws PowerAuthEncryptionException {
        // Only POST HTTP method is supported for ECIES
        if (!"POST".equals(request.getMethod())) {
            logger.warn("Invalid HTTP method: {}", request.getMethod());
            throw new PowerAuthEncryptionException();
        }

        // Resolve either signature or encryption HTTP header for ECIES
        final EncryptionContext encryptionContext = extractEciesEncryptionContext(request, encryptionScope);

        // Construct ECIES encryption object from HTTP header
        final PowerAuthEncryptorData encryptorData = new PowerAuthEncryptorData(encryptionContext);

        try {
            // Parse ECIES cryptogram from request body
            final PowerAuthRequestBody requestBody = ((PowerAuthRequestBody) request.getAttribute(PowerAuthRequestObjects.REQUEST_BODY));
            if (requestBody == null) {
                logger.warn("The X-PowerAuth-Request-Body request attribute is missing. Register the PowerAuthRequestFilter to fix this error.");
                throw new PowerAuthEncryptionException();
            }
            final byte[] requestBodyBytes = requestBody.getRequestBytes();
            if (requestBodyBytes == null || requestBodyBytes.length == 0) {
                logger.warn("Invalid HTTP request");
                throw new PowerAuthEncryptionException();
            }
            final EciesEncryptedRequest eciesRequest;
            try {
                eciesRequest = objectMapper.readValue(requestBodyBytes, EciesEncryptedRequest.class);
            } catch (IOException ex) {
                logger.warn("Request deserialization failed, error: {}", ex.getMessage());
                logger.debug(ex.getMessage(), ex);
                throw new PowerAuthEncryptionException();
            }
            if (eciesRequest == null) {
                logger.warn("Deserialization of request body bytes resulted in null value.");
                throw new PowerAuthEncryptionException();
            }

            // Extract useful properties in advance
            final String version = encryptionContext.getVersion();
            final String applicationKey = encryptionContext.getApplicationKey();
            final String activationId = encryptionContext.getActivationId();

            // Prepare and validate EncryptedRequest object
            final EncryptedRequest encryptedRequest = new EncryptedRequest(
                    eciesRequest.getEphemeralPublicKey(),
                    eciesRequest.getEncryptedData(),
                    eciesRequest.getMac(),
                    eciesRequest.getNonce(),
                    eciesRequest.getTimestamp()
            );
            if (!encryptorFactory.getRequestResponseValidator(version).validateEncryptedRequest(encryptedRequest)) {
                logger.warn("Invalid encrypted request data");
                throw new PowerAuthEncryptionException();
            }
            // Validate presence of activation id for activation scope.
            if (encryptionScope == EncryptionScope.ACTIVATION_SCOPE && activationId == null) {
                logger.warn("Activation ID is required for activation scope");
                throw new PowerAuthEncryptionException();
            }
            // Get encryptor parameters from the PowerAuth Server.
            final PowerAuthEncryptorParameters encryptorParameters = getEciesDecryptorParameters(
                    activationId,
                    applicationKey,
                    encryptedRequest.getEphemeralPublicKey(),
                    version,
                    encryptedRequest.getNonce(),
                    encryptedRequest.getTimestamp()
            );
            // Build server encryptor with obtained encryptor parameters
            final byte[] secretKeyBytes = Base64.getDecoder().decode(encryptorParameters.secretKey());
            final byte[] sharedInfo2Base = Base64.getDecoder().decode(encryptorParameters.sharedInfo2());
            final ServerEncryptor serverEncryptor = encryptorFactory.getServerEncryptor(
                    encryptorData.getEncryptorId(),
                    new EncryptorParameters(version, applicationKey, activationId),
                    new ServerEncryptorSecrets(secretKeyBytes, sharedInfo2Base)
            );

            // Try to decrypt request data
            final byte[] decryptedData = serverEncryptor.decryptRequest(encryptedRequest);

            encryptorData.setEncryptedRequest(encryptedRequest);
            encryptorData.setDecryptedRequest(decryptedData);
            encryptorData.setServerEncryptor(serverEncryptor);

            // Set the request object only in case when request data is sent
            if (decryptedData.length != 0) {
                encryptorData.setRequestObject(deserializeRequestData(decryptedData, requestType));
            }

            // Set encryption object in HTTP servlet request
            request.setAttribute(PowerAuthRequestObjects.ENCRYPTION_OBJECT, encryptorData);
        } catch (Exception ex) {
            logger.warn("Request decryption failed, error: " + ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthEncryptionException();
        }
    }

    /**
     * Encrypt response using End-To-End Encryptor.
     *
     * @param responseObject  Response object which should be encrypted.
     * @param encryption PowerAuth encryption object.
     * @return ECIES encrypted response.
     */
    public @Nullable
    EciesEncryptedResponse encryptResponse(@Nonnull Object responseObject, @Nonnull PowerAuthEncryptorData encryption) {
        try {
            final EncryptionContext encryptionContext = encryption.getContext();
            final ServerEncryptor serverEncryptor = encryption.getServerEncryptor();
            if (encryptionContext == null) {
                logger.warn("Encryption context is not prepared");
                throw new PowerAuthEncryptionException();
            }
            if (serverEncryptor == null || serverEncryptor.canEncryptResponse()) {
                logger.warn("Encryptor is not available or not prepared for encryption. Scope: {}", encryptionContext.getEncryptionScope());
                throw new PowerAuthEncryptionException();
            }
            // Serialize response data
            final byte[] responseData = serializeResponseData(responseObject);
            // Encrypt response
            final EncryptedResponse encryptedResponse = serverEncryptor.encryptResponse(responseData);
            return new EciesEncryptedResponse(
                    encryptedResponse.getEncryptedData(),
                    encryptedResponse.getMac(),
                    encryptedResponse.getNonce(),
                    encryptedResponse.getTimestamp()
            );
        } catch (Exception ex) {
            logger.debug("Response encryption failed, error: " + ex.getMessage(), ex);
            return null;
        }
    }
    
    /**
     * Convert byte[] request data to Object with given type.
     *
     * @param requestData Raw request data.
     * @param requestType Request type.
     * @return Request object.
     * @throws IOException In case request object could not be deserialized.
     */
    private Object deserializeRequestData(byte[] requestData, Type requestType) throws IOException {
        if (requestType.equals(byte[].class)) {
            // Raw byte[] data without deserialization from JSON
            return requestData;
        }
        // Object is deserialized from JSON based on request type
        final TypeFactory typeFactory = objectMapper.getTypeFactory();
        final JavaType requestJavaType = typeFactory.constructType(requestType);
        return objectMapper.readValue(requestData, requestJavaType);
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
     * @param encryptorScope Scope of encryption.
     * @return Context for ECIES encryption.
     * @throws PowerAuthEncryptionException Thrown when HTTP header with ECIES data is invalid.
     */
    private EncryptionContext extractEciesEncryptionContext(HttpServletRequest request, EncryptionScope encryptorScope) throws PowerAuthEncryptionException {
        final String encryptionHttpHeader = request.getHeader(PowerAuthEncryptionHttpHeader.HEADER_NAME);
        final String signatureHttpHeader = request.getHeader(PowerAuthSignatureHttpHeader.HEADER_NAME);

        // Check that at least one PowerAuth HTTP header with parameters for ECIES is present
        if (encryptionHttpHeader == null && signatureHttpHeader == null) {
            logger.warn("Neither signature nor encryption HTTP header is present");
            throw new PowerAuthEncryptionException();
        }

        // In case the PowerAuth signature HTTP header is present, use it for ECIES
        if (signatureHttpHeader != null) {
            // Parse signature HTTP header
            final PowerAuthSignatureHttpHeader header = new PowerAuthSignatureHttpHeader().fromValue(signatureHttpHeader);

            // Validate the signature HTTP header
            try {
                PowerAuthSignatureHttpHeaderValidator.validate(header);
            } catch (InvalidPowerAuthHttpHeaderException ex) {
                logger.warn("Signature HTTP header validation failed, error: {}", ex.getMessage());
                logger.debug(ex.getMessage(), ex);
                throw new PowerAuthEncryptionException();
            }

            // Construct encryption parameters object
            final String applicationKey = header.getApplicationKey();
            final String activationId = header.getActivationId();
            final String version = header.getVersion();
            return new EncryptionContext(applicationKey, activationId, version, header, encryptorScope);
        } else {
            // Parse encryption HTTP header
            final PowerAuthEncryptionHttpHeader header = new PowerAuthEncryptionHttpHeader().fromValue(encryptionHttpHeader);

            // Validate the encryption HTTP header
            try {
                PowerAuthEncryptionHttpHeaderValidator.validate(header, encryptorScope.toEncryptorScope());
            } catch (InvalidPowerAuthHttpHeaderException ex) {
                logger.warn("Encryption validation failed, error: {}", ex.getMessage());
                logger.debug(ex.getMessage(), ex);
                throw new PowerAuthEncryptionException();
            }

            // Construct encryption parameters object
            final String applicationKey = header.getApplicationKey();
            final String activationId = header.getActivationId();
            final String version = header.getVersion();
            return new EncryptionContext(applicationKey, activationId, version, header, encryptorScope);
        }
    }
}
