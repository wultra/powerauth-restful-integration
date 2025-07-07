/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2023 Wultra s.r.o.
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
package com.wultra.security.powerauth.rest.api.spring.util;

import com.wultra.security.powerauth.crypto.lib.encryptor.model.v3.EciesEncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.v4.encryptor.model.request.AeadEncryptedRequest;
import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import lombok.extern.slf4j.Slf4j;

import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Utility class to assist with PowerAuth version checks and related functionalities.
 * This class provides methods to validate different aspects of the PowerAuth protocol,
 * such as version checks, nonce verification, and timestamp checks.
 * <p>
 * Note: The usage of these utility methods ensures the protocol adheres to the correct
 * PowerAuth versions and avoids potential issues in processing requests.
 * </p>
 * @author Jan Dusil, jan.dusil@wultra.com
 */
@Slf4j
public final class PowerAuthVersionUtil {

    /**
     * Prevent instantiation of utility class.
     */
    private PowerAuthVersionUtil() {
        throw new IllegalStateException("Utility class");
    }

    /**
     * Set containing supported versions of PowerAuth protocol V3.
     */
    private static final Set<String> SUPPORTED_VERSIONS_V3 = Set.of("3.0", "3.1", "3.2", "3.3");

    /**
     * Set containing supported versions of PowerAuth protocol V4.
     */
    private static final Set<String> SUPPORTED_VERSIONS_V4 = Set.of("4.0");

    /**
     * Set containing all the supported versions of PowerAuth protocol.
     */
    private static final Set<String> SUPPORTED_VERSIONS = Stream.concat(
            SUPPORTED_VERSIONS_V3.stream(),
            SUPPORTED_VERSIONS_V4.stream()
    ).collect(Collectors.toUnmodifiableSet());

    /**
     * Check if the provided version string is "3.0".
     *
     * @param version Version string to be checked.
     * @return true if the version is "3.0", false otherwise.
     */
    private static boolean isVersion3_0(final String version) {
        return "3.0".equals(version);
    }

    /**
     * Check if the provided version string is "3.1".
     *
     * @param version Version string to be checked.
     * @return true if the version is "3.1", false otherwise.
     */
    private static boolean isVersion3_1(final String version) {
        return "3.1".equals(version);
    }

    /**
     * Check if the provided version string is "3.2".
     *
     * @param version Version string to be checked.
     * @return true if the version is "3.2", false otherwise.
     */
    private static boolean isVersion3_2(final String version) {
        return "3.2".equals(version);
    }

    /**
     * Checks if the provided PowerAuth protocol version is unsupported.
     * Throws an exception if the version is unsupported.
     *
     * @param version Version string to be checked.
     * @throws PowerAuthInvalidRequestException If the provided version is unsupported.
     */
    public static void checkUnsupportedVersion(String version) throws PowerAuthInvalidRequestException {
        if (isUnsupportedVersion(version)) {
            logger.warn("Endpoint does not support PowerAuth protocol version {}", version);
            throw new PowerAuthInvalidRequestException("Endpoint does not support PowerAuth protocol version " + version);
        }
    }

    /**
     * Checks if the provided PowerAuth protocol version is unsupported for V3.
     * Throws an exception if the version is unsupported.
     *
     * @param version Version string to be checked.
     * @throws PowerAuthInvalidRequestException If the provided version is unsupported.
     */
    public static void checkUnsupportedVersionV3(String version) throws PowerAuthInvalidRequestException {
        if (isUnsupportedVersionV3(version)) {
            logger.warn("Version 3 endpoint does not support PowerAuth protocol version {}", version);
            throw new PowerAuthInvalidRequestException("Version 3 endpoint does not support PowerAuth protocol version " + version);
        }
    }

    /**
     * Checks if the provided PowerAuth protocol version is unsupported for V4.
     * Throws an exception if the version is unsupported.
     *
     * @param version Version string to be checked.
     * @throws PowerAuthInvalidRequestException If the provided version is unsupported.
     */
    public static void checkUnsupportedVersionV4(String version) throws PowerAuthInvalidRequestException {
        if (isUnsupportedVersionV4(version)) {
            logger.warn("Version 4 endpoint does not support PowerAuth protocol version {}", version);
            throw new PowerAuthInvalidRequestException("Version 4 endpoint does not support PowerAuth protocol version " + version);
        }
    }

    /**
     * Checks if nonce is missing for the provided PowerAuth protocol version.
     * Throws an exception if nonce is required and missing.
     *
     * @param version Version string to be checked.
     * @param nonce   Nonce string to be verified.
     * @throws PowerAuthInvalidRequestException If nonce is required and missing.
     */
    public static void checkMissingRequiredNonce(String version, String nonce) throws PowerAuthInvalidRequestException {
        if (isMissingRequiredNonce(version, nonce)) {
            logger.warn("Missing nonce in encrypted request data");
            throw new PowerAuthInvalidRequestException("Missing nonce in encrypted request data");
        }
    }

    /**
     * Checks if timestamp is missing for the provided PowerAuth protocol version.
     * Throws an exception if the timestamp is required and missing.
     *
     * @param version   Version string to be checked.
     * @param timestamp Timestamp value to be verified.
     * @throws PowerAuthInvalidRequestException If timestamp is required and missing.
     */
    public static void checkMissingRequiredTimestamp(String version, Long timestamp) throws PowerAuthInvalidRequestException {
        if (isMissingRequiredTimestamp(version, timestamp)) {
            logger.warn("Missing timestamp in encrypted request data for version {}", version);
            throw new PowerAuthInvalidRequestException("Missing timestamp in encrypted request data for version " + version);
        }
    }

    /**
     * Checks if temporary key ID is missing for the provided PowerAuth protocol version.
     * Throws an exception if the temporary key ID is required and missing.
     *
     * @param version   Version string to be checked.
     * @param temporaryKeyId Temporary key ID value to be verified.
     * @throws PowerAuthInvalidRequestException If timestamp is required and missing.
     */
    public static void checkMissingRequiredTemporaryKeyId(String version, String temporaryKeyId) throws PowerAuthInvalidRequestException {
        if (isMissingRequiredTemporaryKeyId(version, temporaryKeyId)) {
            logger.warn("Missing temporary key ID in encrypted request data for version {}", version);
            throw new PowerAuthInvalidRequestException("Missing temporary kdy ID in encrypted request data for version " + version);
        }
    }

    /**
     * Checks if required ECIES encryption parameters are missing for the provided PowerAuth protocol version.
     * Throws an exception if the required parameter is missing.
     *
     * @param version   Version string to be checked.
     * @param request   Request to be verified.
     * @throws PowerAuthInvalidRequestException If timestamp is required and missing.
     */
    public static void checkEncryptionParameters(String version, EciesEncryptedRequest request) throws PowerAuthInvalidRequestException {
        checkMissingRequiredNonce(version, request.getNonce());
        checkMissingRequiredTimestamp(version, request.getTimestamp());
        checkMissingRequiredTemporaryKeyId(version, request.getTemporaryKeyId());
    }

    /**
     * Checks if required AEAD encryption parameters are missing for the provided PowerAuth protocol version.
     * Throws an exception if the required parameter is missing.
     *
     * @param version   Version string to be checked.
     * @param request   Request to be verified.
     * @throws PowerAuthInvalidRequestException If timestamp is required and missing.
     */
    public static void checkEncryptionParameters(String version, AeadEncryptedRequest request) throws PowerAuthInvalidRequestException {
        checkMissingRequiredNonce(version, request.getNonce());
        checkMissingRequiredTimestamp(version, request.getTimestamp());
        checkMissingRequiredTemporaryKeyId(version, request.getTemporaryKeyId());
    }

    /**
     * Checks if the provided PowerAuth protocol version is unsupported.
     *
     * @param version Version string to be checked.
     * @return true if the version is unsupported, false otherwise.
     */
    private static boolean isUnsupportedVersion(String version) {
        return !SUPPORTED_VERSIONS.contains(version);
    }

    /**
     * Checks if the provided PowerAuth protocol version is unsupported for V3.
     *
     * @param version Version string to be checked.
     * @return true if the version is unsupported, false otherwise.
     */
    private static boolean isUnsupportedVersionV3(String version) {
        return !SUPPORTED_VERSIONS_V3.contains(version);
    }

    /**
     * Checks if the provided PowerAuth protocol version is unsupported for V4.
     *
     * @param version Version string to be checked.
     * @return true if the version is unsupported, false otherwise.
     */
    private static boolean isUnsupportedVersionV4(String version) {
        return !SUPPORTED_VERSIONS_V4.contains(version);
    }


    /**
     * Checks if nonce is missing for the provided PowerAuth protocol version.
     *
     * @param version Version string to be checked.
     * @param nonce   Nonce string to be verified.
     * @return true if nonce is required and missing, false otherwise.
     */
    private static boolean isMissingRequiredNonce(String version, String nonce) {
        return nonce == null && !isVersion3_0(version);
    }

    /**
     * Checks if timestamp is missing for the provided PowerAuth protocol version.
     *
     * @param version   Version string to be checked.
     * @param timestamp Timestamp value to be verified.
     * @return true if timestamp is required and missing, false otherwise.
     */
    private static boolean isMissingRequiredTimestamp(String version, Long timestamp) {
        return timestamp == null &&
                !isVersion3_0(version) &&
                !isVersion3_1(version);
    }

    /**
     * Checks if temporary key ID is missing for the provided PowerAuth protocol version.
     *
     * @param version   Version string to be checked.
     * @param temporaryKeyId Temporary key ID
     * @return true if temporary key ID is required and missing, false otherwise.
     */
    private static boolean isMissingRequiredTemporaryKeyId(String version, String temporaryKeyId) {
        return temporaryKeyId == null &&
                !isVersion3_0(version) &&
                !isVersion3_1(version) &&
                !isVersion3_2(version);
    }

}
