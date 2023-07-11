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
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesDecryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEncryptor;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesEnvelopeKey;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.EciesFactory;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesCryptogram;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesParameters;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesPayload;
import io.getlime.security.powerauth.crypto.lib.encryptor.ecies.model.EciesScope;
import io.getlime.security.powerauth.crypto.lib.generator.KeyGenerator;
import io.getlime.security.powerauth.crypto.lib.util.ByteUtils;
import io.getlime.security.powerauth.http.PowerAuthEncryptionHttpHeader;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.http.validator.InvalidPowerAuthHttpHeaderException;
import io.getlime.security.powerauth.http.validator.PowerAuthEncryptionHttpHeaderValidator;
import io.getlime.security.powerauth.http.validator.PowerAuthSignatureHttpHeaderValidator;
import io.getlime.security.powerauth.rest.api.model.request.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.EciesEncryptedResponse;
import io.getlime.security.powerauth.rest.api.spring.encryption.EciesEncryptionContext;
import io.getlime.security.powerauth.rest.api.spring.encryption.PowerAuthEciesDecryptorParameters;
import io.getlime.security.powerauth.rest.api.spring.encryption.PowerAuthEciesEncryption;
import io.getlime.security.powerauth.rest.api.spring.encryption.PowerAuthEciesEncryptorParameters;
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
import java.util.Date;

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
    private final EciesFactory eciesFactory = new EciesFactory();
    private final KeyGenerator keyGenerator = new KeyGenerator();

    /**
     * Get ECIES decryptor parameters from PowerAuth server.
     *
     * @param activationId Activation ID (only used in activation scope, in application scope use null).
     * @param applicationKey Application key.
     * @param ephemeralPublicKey Ephemeral public key for ECIES.
     * @return ECIES decryptor parameters.
     * @throws PowerAuthEncryptionException In case PowerAuth server call fails.
     */
    public abstract @Nonnull PowerAuthEciesDecryptorParameters getEciesDecryptorParameters(@Nullable String activationId, @Nonnull String applicationKey, @Nonnull String ephemeralPublicKey) throws PowerAuthEncryptionException;

    /**
     * Get ECIES encryptor parameters from PowerAuth server.
     *
     * @param activationId Activation ID (only used in activation scope, in application scope use null).
     * @param applicationKey Application key.
     * @param ephemeralPublicKey Ephemeral public key for ECIES.
     * @return ECIES encryptor parameters.
     * @throws PowerAuthEncryptionException In case PowerAuth server call fails.
     */
    public abstract @Nonnull PowerAuthEciesEncryptorParameters getEciesEncryptorParameters(@Nullable String activationId, @Nonnull String applicationKey, @Nonnull String ephemeralPublicKey) throws PowerAuthEncryptionException;

    /**
     * Decrypt HTTP request body and construct object with ECIES data. Use the requestType parameter to specify
     * the type of decrypted object.
     *
     * @param request HTTP request.
     * @param requestType Class of request object.
     * @param eciesScope ECIES scope.
     * @return Object with ECIES data.
     * @throws PowerAuthEncryptionException In case request decryption fails.
     */
    public @Nonnull PowerAuthEciesEncryption decryptRequest(@Nonnull HttpServletRequest request, @Nonnull Type requestType, @Nonnull EciesScope eciesScope) throws PowerAuthEncryptionException {
        // Only POST HTTP method is supported for ECIES
        if (!"POST".equals(request.getMethod())) {
            logger.warn("Invalid HTTP method: {}", request.getMethod());
            throw new PowerAuthEncryptionException();
        }

        // Resolve either signature or encryption HTTP header for ECIES
        final EciesEncryptionContext encryptionContext = extractEciesEncryptionContext(request);

        // Construct ECIES encryption object from HTTP header
        final PowerAuthEciesEncryption eciesEncryption = new PowerAuthEciesEncryption(encryptionContext);

        // Save ECIES scope in context
        eciesEncryption.getContext().setEciesScope(eciesScope);

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

            // Prepare ephemeral public key
            final String ephemeralPublicKey = eciesRequest.getEphemeralPublicKey();
            final String encryptedData = eciesRequest.getEncryptedData();
            final String mac = eciesRequest.getMac();
            final String nonce = eciesRequest.getNonce();
            final Long timestamp = eciesRequest.getTimestamp();

            // Verify ECIES request data. Nonce is required for protocol 3.1+
            if (ephemeralPublicKey == null || encryptedData == null || mac == null) {
                logger.warn("Invalid ECIES request data");
                throw new PowerAuthEncryptionException();
            }
            if (nonce == null && !"3.0".equals(encryptionContext.getVersion())) {
                logger.warn("Missing nonce in ECIES request data");
                throw new PowerAuthEncryptionException();
            }
            if (timestamp == null && (!"3.0".equals(encryptionContext.getVersion()) && !"3.1".equals(encryptionContext.getVersion()))) {
                logger.warn("Missing timestamp in ECIES request data");
                throw new PowerAuthEncryptionException();
            }

            // Save ephemeral public key in context
            eciesEncryption.getContext().setEphemeralPublicKey(ephemeralPublicKey);

            final byte[] ephemeralPublicKeyBytes = Base64.getDecoder().decode(ephemeralPublicKey);
            final byte[] encryptedDataBytes = Base64.getDecoder().decode(encryptedData);
            final byte[] macBytes = Base64.getDecoder().decode(mac);
            final byte[] nonceBytes = nonce != null ? Base64.getDecoder().decode(nonce) : null;

            final String applicationKey = eciesEncryption.getContext().getApplicationKey();
            final PowerAuthEciesDecryptorParameters decryptorParameters;
            // Obtain ECIES decryptor parameters from PowerAuth server
            final byte[] associatedData;
            switch (eciesScope) {
                case ACTIVATION_SCOPE -> {
                    final String activationId = eciesEncryption.getContext().getActivationId();
                    if (activationId == null) {
                        logger.warn("Activation ID is required in ECIES activation scope");
                        throw new PowerAuthEncryptionException();
                    }
                    decryptorParameters = getEciesDecryptorParameters(activationId, applicationKey, ephemeralPublicKey);
                    associatedData = "3.2".equals(encryptionContext.getVersion()) ? deriveAssociatedData(EciesScope.ACTIVATION_SCOPE, encryptionContext.getVersion(), applicationKey, activationId) : null;
                }
                case APPLICATION_SCOPE -> {
                    decryptorParameters = getEciesDecryptorParameters(null, applicationKey, ephemeralPublicKey);
                    associatedData = "3.2".equals(encryptionContext.getVersion()) ? deriveAssociatedData(EciesScope.APPLICATION_SCOPE, encryptionContext.getVersion(), applicationKey, null) : null;
                }
                default -> {
                    logger.warn("Unsupported ECIES scope: {}", eciesScope);
                    throw new PowerAuthEncryptionException();
                }
            }

            // Prepare envelope key and sharedInfo2 parameter for decryptor
            final byte[] secretKey = Base64.getDecoder().decode(decryptorParameters.secretKey());
            final EciesEnvelopeKey envelopeKey = new EciesEnvelopeKey(secretKey, ephemeralPublicKeyBytes);
            final byte[] sharedInfo2 = Base64.getDecoder().decode(decryptorParameters.sharedInfo2());

            // Construct decryptor and set it to the request for later encryption of response
            final EciesDecryptor eciesDecryptor = eciesFactory.getEciesDecryptor(envelopeKey, sharedInfo2);
            eciesEncryption.setEciesDecryptor(eciesDecryptor);

            // Decrypt request data
            final EciesParameters parameters = EciesParameters.builder().nonce(nonceBytes).associatedData(associatedData).timestamp(timestamp).build();
            final EciesCryptogram cryptogram = EciesCryptogram.builder().encryptedData(encryptedDataBytes).mac(macBytes).ephemeralPublicKey(ephemeralPublicKeyBytes).build();
            final EciesPayload payload = new EciesPayload(cryptogram, parameters);
            final byte[] decryptedData = eciesDecryptor.decrypt(payload);
            eciesEncryption.setEncryptedRequest(encryptedDataBytes);
            eciesEncryption.setDecryptedRequest(decryptedData);
            eciesEncryption.setAssociatedData(associatedData);
            // Set the request object only in case when request data is sent
            if (decryptedData.length != 0) {
                eciesEncryption.setRequestObject(deserializeRequestData(decryptedData, requestType));
            }

            // Set encryption object in HTTP servlet request
            request.setAttribute(PowerAuthRequestObjects.ENCRYPTION_OBJECT, eciesEncryption);
        } catch (Exception ex) {
            logger.warn("Request decryption failed, error: " + ex.getMessage());
            logger.debug(ex.getMessage(), ex);
            throw new PowerAuthEncryptionException();
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
    public @Nullable EciesEncryptedResponse encryptResponse(@Nonnull Object responseObject, @Nonnull PowerAuthEciesEncryption eciesEncryption) {
        try {
            final EciesEncryptionContext encryptionContext = eciesEncryption.getContext();
            final EciesScope eciesScope = encryptionContext.getEciesScope();

            final String applicationKey = eciesEncryption.getContext().getApplicationKey();
            final String ephemeralPublicKey = eciesEncryption.getContext().getEphemeralPublicKey();
            final byte[] ephemeralPublicKeyBytes = Base64.getDecoder().decode(ephemeralPublicKey);

            final PowerAuthEciesEncryptorParameters encryptorParameters;
            // Obtain ECIES decryptor parameters from PowerAuth server
            final byte[] associatedData;
            switch (eciesScope) {
                case ACTIVATION_SCOPE -> {
                    final String activationId = eciesEncryption.getContext().getActivationId();
                    if (activationId == null) {
                        logger.warn("Activation ID is required in ECIES activation scope");
                        throw new PowerAuthEncryptionException();
                    }
                    encryptorParameters = getEciesEncryptorParameters(activationId, applicationKey, ephemeralPublicKey);
                    associatedData = "3.2".equals(encryptionContext.getVersion()) ? deriveAssociatedData(EciesScope.ACTIVATION_SCOPE, encryptionContext.getVersion(), applicationKey, activationId) : null;
                }
                case APPLICATION_SCOPE -> {
                    encryptorParameters = getEciesEncryptorParameters(null, applicationKey, ephemeralPublicKey);
                    associatedData = "3.2".equals(encryptionContext.getVersion()) ? deriveAssociatedData(EciesScope.APPLICATION_SCOPE, encryptionContext.getVersion(), applicationKey, null) : null;
                }
                default -> {
                    logger.warn("Unsupported ECIES scope: {}", eciesScope);
                    throw new PowerAuthEncryptionException();
                }
            }

            // Prepare envelope key and sharedInfo2 parameter for encryptor
            final byte[] secretKey = Base64.getDecoder().decode(encryptorParameters.secretKey());
            final EciesEnvelopeKey envelopeKey = new EciesEnvelopeKey(secretKey, ephemeralPublicKeyBytes);
            final byte[] sharedInfo2 = Base64.getDecoder().decode(encryptorParameters.sharedInfo2());

            final byte[] responseData = serializeResponseData(responseObject);
            // Encrypt response using encryptor and return ECIES cryptogram
            final String version = eciesEncryption.getContext().getVersion();
            final byte[] nonceBytesResponse = "3.2".equals(version) ? keyGenerator.generateRandomBytes(16) : null;
            final Long timestampResponse = "3.2".equals(version) ? new Date().getTime() : null;
            final EciesParameters parametersResponse = EciesParameters.builder().nonce(nonceBytesResponse).associatedData(associatedData).timestamp(timestampResponse).build();
            final EciesEncryptor encryptor = eciesFactory.getEciesEncryptor(envelopeKey, sharedInfo2);
            // Store ECIES encryptor
            eciesEncryption.setEciesEncryptor(encryptor);

            final EciesPayload payload = encryptor.encrypt(responseData, parametersResponse);
            final String encryptedDataBase64 = Base64.getEncoder().encodeToString(payload.getCryptogram().getEncryptedData());
            final String macBase64 = Base64.getEncoder().encodeToString(payload.getCryptogram().getMac());
            return new EciesEncryptedResponse(encryptedDataBase64, macBase64);
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
     * @return Context for ECIES encryption.
     * @throws PowerAuthEncryptionException Thrown when HTTP header with ECIES data is invalid.
     */
    private EciesEncryptionContext extractEciesEncryptionContext(HttpServletRequest request) throws PowerAuthEncryptionException {
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
            return new EciesEncryptionContext(applicationKey, activationId, version, header);
        } else {
            // Parse encryption HTTP header
            final PowerAuthEncryptionHttpHeader header = new PowerAuthEncryptionHttpHeader().fromValue(encryptionHttpHeader);

            // Validate the encryption HTTP header
            try {
                PowerAuthEncryptionHttpHeaderValidator.validate(header);
            } catch (InvalidPowerAuthHttpHeaderException ex) {
                logger.warn("Encryption validation failed, error: {}", ex.getMessage());
                logger.debug(ex.getMessage(), ex);
                throw new PowerAuthEncryptionException();
            }

            // Construct encryption parameters object
            final String applicationKey = header.getApplicationKey();
            final String activationId = header.getActivationId();
            final String version = header.getVersion();
            return new EciesEncryptionContext(applicationKey, activationId, version, header);
        }
    }

    /**
     * Derive associated data.
     * @param eciesScope ECIES scope.
     * @param version Crypto protocol version.
     * @param applicationKey Application key.
     * @param activationId Activation ID.
     * @return Associated data as byte array.
     */
    private byte[] deriveAssociatedData(EciesScope eciesScope, String version, String applicationKey, String activationId) {
        if ("3.2".equals(version)) {
            if (eciesScope == EciesScope.ACTIVATION_SCOPE) {
                return ByteUtils.concatStrings(version, applicationKey, activationId);
            } else {
                return ByteUtils.concatStrings(version, applicationKey);
            }
        } else {
            return null;
        }
    }
}
