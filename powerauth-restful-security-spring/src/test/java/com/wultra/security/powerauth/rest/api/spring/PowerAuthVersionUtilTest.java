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
package com.wultra.security.powerauth.rest.api.spring;

import com.wultra.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import com.wultra.security.powerauth.rest.api.spring.util.PowerAuthVersionUtil;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * This class provides tests for the {@link PowerAuthVersionUtil} utility class,
 * ensuring that the PowerAuth version checks and related functionalities work as expected.
 *
 * @author Jan Dusil, jan.dusil@wultra.com
 */
class PowerAuthVersionUtilTest {

    /**
     * Tests the behavior of checking unsupported PowerAuth versions.
     */
    @Test
    void testUnsupportedVersion() {
        assertThrows(PowerAuthInvalidRequestException.class, () -> PowerAuthVersionUtil.checkUnsupportedVersion("4.0"));
        assertDoesNotThrow(() -> PowerAuthVersionUtil.checkUnsupportedVersion("3.1"));
    }

    /**
     * Tests the behavior of checking for missing required nonces based on the PowerAuth version.
     */
    @Test
    void testMissingRequiredNonce() {
        assertThrows(PowerAuthInvalidRequestException.class, () -> PowerAuthVersionUtil.checkMissingRequiredNonce("3.1", null));
        assertDoesNotThrow(() -> PowerAuthVersionUtil.checkMissingRequiredNonce("3.0", null));
        assertDoesNotThrow(() -> PowerAuthVersionUtil.checkMissingRequiredNonce("3.1", "testNonce"));
    }

    /**
     * Tests the behavior of checking for missing required timestamps based on the PowerAuth version.
     */
    @Test
    void testMissingRequiredTimestamp() {
        assertThrows(PowerAuthInvalidRequestException.class, () -> PowerAuthVersionUtil.checkMissingRequiredTimestamp("3.2", null));
        assertDoesNotThrow(() -> PowerAuthVersionUtil.checkMissingRequiredTimestamp("3.1", null));
        assertDoesNotThrow(() -> PowerAuthVersionUtil.checkMissingRequiredTimestamp("3.2", 1630234567890L));
    }

    @Test
    void testMissingRequiredTemporaryKeyId() {
        assertThrows(PowerAuthInvalidRequestException.class, () -> PowerAuthVersionUtil.checkMissingRequiredTemporaryKeyId("3.3", null));
        assertDoesNotThrow(() -> PowerAuthVersionUtil.checkMissingRequiredTemporaryKeyId("3.1", null));
        assertDoesNotThrow(() -> PowerAuthVersionUtil.checkMissingRequiredTemporaryKeyId("3.2", null));
        assertDoesNotThrow(() -> PowerAuthVersionUtil.checkMissingRequiredTemporaryKeyId("3.3", UUID.randomUUID().toString()));
    }
}