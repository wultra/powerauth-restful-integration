package io.getlime.security.powerauth.rest.api.spring.util;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

@Slf4j
public class PowerAuthVersionUtil {

    private enum PowerAuthVersion {
        V3_0("3.0"),
        V3_1("3.1"),
        V3_2("3.2");

        private final String versionString;

        PowerAuthVersion(String versionString) {
            this.versionString = versionString;
        }

        public String getVersionString() {
            return versionString;
        }

        private static final Map<String, PowerAuthVersion> LOOKUP = new HashMap<>();

        static {
            for (PowerAuthVersion v : PowerAuthVersion.values()) {
                LOOKUP.put(v.getVersionString(), v);
            }
        }

        public static PowerAuthVersion fromString(String version) {
            return LOOKUP.get(version);
        }
    }

    public static boolean isUnsupportedVersion(String version) {
       return PowerAuthVersion.fromString(version) == null;
    }

    public static boolean isMissingRequiredNonce(String version, String nonce) {
        return nonce == null && !version.equals(PowerAuthVersion.V3_0.getVersionString());
    }

    public static boolean isMissingRequiredTimestamp(String version, Long timestamp) {
        return timestamp == null &&
                !version.equals(PowerAuthVersion.V3_0.getVersionString()) &&
                !version.equals(PowerAuthVersion.V3_1.getVersionString());
    }


    @SneakyThrows
    public static void checkUnsupportedVersion(String version, Supplier<? extends Exception> exceptionSupplier) {
        if (isUnsupportedVersion(version)) {
            logger.warn("Endpoint does not support PowerAuth protocol version {}", version);
            throw exceptionSupplier.get();
        }
    }

    @SneakyThrows
    public static void checkMissingRequiredNonce(String version, String nonce, Supplier<? extends Exception> exceptionSupplier) {
        if (isMissingRequiredNonce(nonce, version)) {
            logger.warn("Missing nonce in ECIES request data");
            throw exceptionSupplier.get();
        }
    }

    @SneakyThrows
    public static void checkMissingRequiredTimestamp(String version, Long timestamp, Supplier<? extends Exception> exceptionSupplier) {
        if (isMissingRequiredTimestamp(version, timestamp)) {
            logger.warn("Missing timestamp in ECIES request data for version {}", version);
            throw exceptionSupplier.get();
        }
    }

}
