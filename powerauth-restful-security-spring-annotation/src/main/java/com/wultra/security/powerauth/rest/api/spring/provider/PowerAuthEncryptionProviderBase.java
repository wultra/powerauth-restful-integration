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
package com.wultra.security.powerauth.rest.api.spring.provider;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.TypeFactory;
import com.wultra.security.powerauth.crypto.lib.encryptor.EncryptorFactory;
import com.wultra.security.powerauth.crypto.lib.encryptor.ServerEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptedResponse;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorParameters;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorSecrets;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.ServerEciesSecrets;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.context.AeadSecrets;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.request.AeadEncryptedRequest;
import com.wultra.security.powerauth.http.PowerAuthEncryptionHttpHeader;
import com.wultra.security.powerauth.http.PowerAuthAuthorizationHttpHeader;
import com.wultra.security.powerauth.http.validator.InvalidPowerAuthHttpHeaderException;
import com.wultra.security.powerauth.http.validator.PowerAuthEncryptionHttpHeaderValidator;
import com.wultra.security.powerauth.http.validator.PowerAuthAuthorizationHttpHeaderValidator;
import com.wultra.security.powerauth.rest.api.spring.encryption.EncryptionContext;
import com.wultra.security.powerauth.rest.api.spring.encryption.EncryptionScope;
import com.wultra.security.powerauth.rest.api.spring.encryption.PowerAuthEncryptorData;
import com.wultra.security.powerauth.rest.api.spring.encryption.PowerAuthEncryptorParameters;
import com.wultra.security.powerauth.rest.api.spring.exception.PowerAuthEncryptionException;
import com.wultra.security.powerauth.rest.api.spring.model.ActivationStatus;
import com.wultra.security.powerauth.rest.api.spring.model.PowerAuthRequestBody;
import com.wultra.security.powerauth.rest.api.spring.model.PowerAuthRequestObjects;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
     * Get ECIES encryptor parameters from PowerAuth server.
     *
     * @param activationId       Activation ID (only used in activation scope, in application scope use null).
     * @param applicationKey     Application key.
     * @param temporaryKeyId     Temporary key ID.
     * @param ephemeralPublicKey Ephemeral public key.
     * @param version            Protocol version.
     * @param nonce              Nonce.
     * @param timestamp          Timestamp.
     * @return ECIES Encryptor parameters.
     * @throws PowerAuthEncryptionException In case PowerAuth server call fails.
     */
    public abstract @Nonnull PowerAuthEncryptorParameters getEciesEncryptorParameters(@Nullable String activationId, @Nonnull String applicationKey, @Nonnull String temporaryKeyId, @Nonnull String ephemeralPublicKey, @Nonnull String version, @Nullable String nonce, @Nullable Long timestamp) throws PowerAuthEncryptionException;

    /**
     * Get AEAD encryptor parameters from PowerAuth server.
     *
     * @param activationId       Activation ID (only used in activation scope, in application scope use null).
     * @param applicationKey     Application key.
     * @param temporaryKeyId     Temporary key ID.
     * @param version            Protocol version.
     * @param nonce              Nonce.
     * @param timestamp          Timestamp.
     * @param allowedStates      Allowed activation states for obtaining encryptor in activation scope.
     * @return AEAD encryptor parameters.
     * @throws PowerAuthEncryptionException In case PowerAuth server call fails.
     */
    public abstract @Nonnull PowerAuthEncryptorParameters getAeadEncryptorParameters(@Nullable String activationId, @Nonnull String applicationKey, @Nonnull String temporaryKeyId, @Nonnull String version, @Nonnull String nonce, @Nonnull Long timestamp, @Nonnull ActivationStatus[] allowedStates) throws PowerAuthEncryptionException;

    /**
     * Decrypt HTTP request body and construct object with encryption data. Use the requestType parameter to specify
     * the type of decrypted object.
     *
     * @param request         HTTP request.
     * @param requestType     Class of request object.
     * @param encryptionScope Encryption scope.
     * @param allowedStates   Allowed activation states for obtaining encryptor in activation scope.
     * @throws PowerAuthEncryptionException In case request decryption fails.
     */
    public void decryptRequest(@Nonnull HttpServletRequest request, @Nonnull Type requestType, @Nonnull EncryptionScope encryptionScope, @Nonnull ActivationStatus[] allowedStates) throws PowerAuthEncryptionException {
        // Only POST HTTP method is supported for encryption
        if (!"POST".equals(request.getMethod())) {
            logger.warn("Invalid HTTP method: {}", request.getMethod());
            throw new PowerAuthEncryptionException();
        }

        // Resolve either authorization or encryption HTTP header for encryption
        final EncryptionContext encryptionContext = extractEncryptionContext(request, encryptionScope);

        // Construct encryption object from HTTP header
        final PowerAuthEncryptorData encryptorData = new PowerAuthEncryptorData(encryptionContext);

        try {
            // Parse cryptogram from request body
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

            // Extract useful properties in advance
            final String applicationKey = encryptionContext.getApplicationKey();
            final String activationId = encryptionContext.getActivationId();
            final String version = encryptionContext.getVersion();
            if (!version.matches("^\\d+\\.\\d+$")) {
                logger.warn("Invalid version: " + version);
                throw new PowerAuthEncryptionException();
            }
            final int majorVersion = Integer.parseInt(version.split("\\.")[0]);

            final EncryptedRequest encryptedRequest;
            final PowerAuthEncryptorParameters encryptorParameters;
            final EncryptorSecrets encryptorSecrets;
            final String temporaryKeyId;
            switch (majorVersion) {
                case 3:
                    final EciesEncryptedRequest eciesRequest = deserializeRequest(requestBodyBytes, EciesEncryptedRequest.class);
                    temporaryKeyId = eciesRequest.getTemporaryKeyId();
                    encryptedRequest = new EciesEncryptedRequest(
                            temporaryKeyId,
                            eciesRequest.getEphemeralPublicKey(),
                            eciesRequest.getEncryptedData(),
                            eciesRequest.getMac(),
                            eciesRequest.getNonce(),
                            eciesRequest.getTimestamp()
                    );
                    encryptorParameters = getEciesEncryptorParameters(
                            activationId,
                            applicationKey,
                            temporaryKeyId,
                            eciesRequest.getEphemeralPublicKey(),
                            version,
                            eciesRequest.getNonce(),
                            eciesRequest.getTimestamp()
                    );
                    final byte[] secretKeyBytesEcies = Base64.getDecoder().decode(encryptorParameters.secretKey());
                    final byte[] sharedInfo2BaseEcies = Base64.getDecoder().decode(encryptorParameters.sharedInfo2());
                    encryptorSecrets = new ServerEciesSecrets(secretKeyBytesEcies, sharedInfo2BaseEcies);
                    break;
                case 4:
                    final AeadEncryptedRequest aeadRequest = deserializeRequest(requestBodyBytes, AeadEncryptedRequest.class);
                    temporaryKeyId = aeadRequest.getTemporaryKeyId();
                    encryptedRequest = new AeadEncryptedRequest(
                            temporaryKeyId,
                            aeadRequest.getEncryptedData(),
                            aeadRequest.getNonce(),
                            aeadRequest.getTimestamp()
                    );
                    encryptorParameters = getAeadEncryptorParameters(
                            activationId,
                            applicationKey,
                            temporaryKeyId,
                            version,
                            aeadRequest.getNonce(),
                            aeadRequest.getTimestamp(),
                            allowedStates
                    );
                    final byte[] secretKeyBytesAead = Base64.getDecoder().decode(encryptorParameters.secretKey());
                    final byte[] sharedInfo2BaseAead = Base64.getDecoder().decode(encryptorParameters.sharedInfo2());
                    encryptorSecrets = new AeadSecrets(secretKeyBytesAead, sharedInfo2BaseAead);
                    break;
                default:
                    logger.warn("Unsupported version: " + version);
                    throw new PowerAuthEncryptionException();
            }

            // Prepare and validate EncryptedRequest object
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

            // Build server encryptor with obtained encryptor parameters
            final ServerEncryptor<EncryptedRequest, EncryptedResponse> serverEncryptor = encryptorFactory.getServerEncryptor(
                    encryptorData.getEncryptorId(),
                    new EncryptorParameters(version, applicationKey, activationId, temporaryKeyId),
                    encryptorSecrets
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
     * Deserialize an encrypted request.
     * @param requestBodyBytes Request body bytes.
     * @param type Request type class.
     * @return Deserialized request.
     * @param <T> Request type.
     * @throws PowerAuthEncryptionException In case deserialization fails.
     */
    private <T> T deserializeRequest(byte[] requestBodyBytes, Class<T> type) throws PowerAuthEncryptionException {
        final T request;
        try {
            request = objectMapper.readValue(requestBodyBytes, type);
        } catch (IOException ex) {
            logger.warn("Request deserialization failed, error: {}", ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthEncryptionException();
        }
        if (request == null) {
            logger.warn("Deserialization of request body bytes resulted in null value.");
            throw new PowerAuthEncryptionException();
        }
        return request;
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
     * Extract context required for encryption from either encryption or authorization HTTP header.
     *
     * @param request HTTP servlet request.
     * @param encryptorScope Scope of encryption.
     * @return Context for encryption.
     * @throws PowerAuthEncryptionException Thrown when HTTP header with encryption data is invalid.
     */
    private EncryptionContext extractEncryptionContext(HttpServletRequest request, EncryptionScope encryptorScope) throws PowerAuthEncryptionException {
        final String encryptionHttpHeader = request.getHeader(PowerAuthEncryptionHttpHeader.HEADER_NAME);
        final String authorizationHttpHeader = request.getHeader(PowerAuthAuthorizationHttpHeader.HEADER_NAME);

        // Check that at least one PowerAuth HTTP header with parameters for ECIES is present
        if (encryptionHttpHeader == null && authorizationHttpHeader == null) {
            logger.warn("Neither authorization nor encryption HTTP header is present");
            throw new PowerAuthEncryptionException();
        }

        // In case the PowerAuth authorization HTTP header is present, use it for ECIES
        if (authorizationHttpHeader != null) {
            // Parse the authorization HTTP header
            final PowerAuthAuthorizationHttpHeader header = new PowerAuthAuthorizationHttpHeader().fromValue(authorizationHttpHeader);

            // Validate the authorization HTTP header
            try {
                PowerAuthAuthorizationHttpHeaderValidator.validate(header);
            } catch (InvalidPowerAuthHttpHeaderException ex) {
                logger.warn("Authorization HTTP header validation failed, error: {}", ex.getMessage());
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
