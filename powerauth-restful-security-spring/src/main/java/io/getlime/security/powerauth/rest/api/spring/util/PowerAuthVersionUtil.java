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
package io.getlime.security.powerauth.rest.api.spring.util;

import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import lombok.extern.slf4j.Slf4j;

import java.util.Set;

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
     * Set containing all the supported versions of PowerAuth.
     */
    private static final Set<String> SUPPORTED_VERSIONS = Set.of("3.0", "3.1", "3.2");

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
     * Checks if nonce is missing for the provided PowerAuth protocol version.
     * Throws an exception if nonce is required and missing.
     *
     * @param version Version string to be checked.
     * @param nonce   Nonce string to be verified.
     * @throws PowerAuthInvalidRequestException If nonce is required and missing.
     */
    public static void checkMissingRequiredNonce(String version, String nonce) throws PowerAuthInvalidRequestException {
        if (isMissingRequiredNonce(version, nonce)) {
            logger.warn("Missing nonce in ECIES request data");
            throw new PowerAuthInvalidRequestException("Missing nonce in ECIES request data");
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
            logger.warn("Missing timestamp in ECIES request data for version {}", version);
            throw new PowerAuthInvalidRequestException("Missing timestamp in ECIES request data for version " + version);
        }
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
}
