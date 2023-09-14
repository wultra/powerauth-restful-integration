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

import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Utility class to assist with PowerAuth version checks and related functionalities.
 *
 * @author Jan Dusil, jan.dusil@wultra.com
 */
@Slf4j
public class PowerAuthVersionUtil {

    /**
     * Enumeration representing supported PowerAuth versions.
     */
    private enum PowerAuthVersion {
        V3_0("3.0"),
        V3_1("3.1"),
        V3_2("3.2");

        private final String versionString;

        PowerAuthVersion(String versionString) {
            this.versionString = versionString;
        }

        /**
         * Get the string representation of the PowerAuth version.
         *
         * @return the version as a string
         */
        public String getVersionString() {
            return versionString;
        }

        private static final Map<String, PowerAuthVersion> LOOKUP = new HashMap<>();

        static {
            for (PowerAuthVersion v : PowerAuthVersion.values()) {
                LOOKUP.put(v.getVersionString(), v);
            }
        }

        /**
         * Retrieve a PowerAuthVersion instance from its string representation.
         *
         * @param version the version as a string
         * @return the corresponding PowerAuthVersion, or null if the version is not recognized
         */
        public static PowerAuthVersion fromString(String version) {
            return LOOKUP.get(version);
        }
    }

    /**
     * Check for unsupported version and throws an exception if unsupported.
     *
     * @param version           the version to check
     * @param exceptionSupplier supplies the exception to be thrown
     * @param <T>               the type of exception to be thrown
     * @throws T if the version is unsupported
     */
    public static <T extends Exception> void checkUnsupportedVersion(String version, Supplier<T> exceptionSupplier) throws T {
        if (isUnsupportedVersion(version)) {
            logger.warn("Endpoint does not support PowerAuth protocol version {}", version);
            throw exceptionSupplier.get();
        }
    }

    /**
     * Check for missing nonce and throws an exception if missing.
     *
     * @param version           the version to check
     * @param nonce             the nonce to verify
     * @param exceptionSupplier supplies the exception to be thrown
     * @param <T>               the type of exception to be thrown
     * @throws T if nonce is required and missing
     */
    public static <T extends Exception> void checkMissingRequiredNonce(String version, String nonce, Supplier<T> exceptionSupplier) throws T {
        if (isMissingRequiredNonce(nonce, version)) {
            logger.warn("Missing nonce in ECIES request data");
            throw exceptionSupplier.get();
        }
    }

    /**
     * Check for missing timestamp and throws an exception if missing.
     *
     * @param version           the version to check
     * @param timestamp         the timestamp to verify
     * @param exceptionSupplier supplies the exception to be thrown
     * @param <T>               the type of exception to be thrown
     * @throws T if timestamp is required and missing
     */
    public static <T extends Exception> void checkMissingRequiredTimestamp(String version, Long timestamp, Supplier<T> exceptionSupplier) throws T {
        if (isMissingRequiredTimestamp(version, timestamp)) {
            logger.warn("Missing timestamp in ECIES request data for version {}", version);
            throw exceptionSupplier.get();
        }
    }

    /**
     * Check if the given version is unsupported.
     *
     * @param version the version to check
     * @return true if the version is unsupported, false otherwise
     */
    private static boolean isUnsupportedVersion(String version) {
        return PowerAuthVersion.fromString(version) == null;
    }

    /**
     * Check if nonce is missing for a given version.
     *
     * @param version the version to check
     * @param nonce   the nonce to verify
     * @return true if nonce is required and missing, false otherwise
     */
    private static boolean isMissingRequiredNonce(String version, String nonce) {
        return nonce == null && !version.equals(PowerAuthVersion.V3_0.getVersionString());
    }

    /**
     * Check if timestamp is missing for a given version.
     *
     * @param version   the version to check
     * @param timestamp the timestamp to verify
     * @return true if timestamp is required and missing, false otherwise
     */
    private static boolean isMissingRequiredTimestamp(String version, Long timestamp) {
        return timestamp == null &&
                !version.equals(PowerAuthVersion.V3_0.getVersionString()) &&
                !version.equals(PowerAuthVersion.V3_1.getVersionString());
    }
}
