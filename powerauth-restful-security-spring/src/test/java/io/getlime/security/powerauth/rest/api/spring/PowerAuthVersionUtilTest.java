package io.getlime.security.powerauth.rest.api.spring;/*
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


import io.getlime.security.powerauth.rest.api.spring.exception.authentication.PowerAuthInvalidRequestException;
import io.getlime.security.powerauth.rest.api.spring.util.PowerAuthVersionUtil;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PowerAuthVersionUtilTest {

    @Test
    void testUnsupportedVersion() {
        assertThrows(PowerAuthInvalidRequestException.class, () -> PowerAuthVersionUtil.checkUnsupportedVersion("4.0"));
        assertDoesNotThrow(() -> PowerAuthVersionUtil.checkUnsupportedVersion("3.1"));
    }

    @Test
    void testMissingRequiredNonce() {
        assertThrows(PowerAuthInvalidRequestException.class, () -> PowerAuthVersionUtil.checkMissingRequiredNonce("3.1", null));
        assertDoesNotThrow(() -> PowerAuthVersionUtil.checkMissingRequiredNonce("3.0", null));
        assertDoesNotThrow(() -> PowerAuthVersionUtil.checkMissingRequiredNonce("3.1", "testNonce"));
    }

    @Test
    void testMissingRequiredTimestamp() {
        assertThrows(PowerAuthInvalidRequestException.class, () -> PowerAuthVersionUtil.checkMissingRequiredTimestamp("3.2", null));
        assertDoesNotThrow(() -> PowerAuthVersionUtil.checkMissingRequiredTimestamp("3.1", null));
        assertDoesNotThrow(() -> PowerAuthVersionUtil.checkMissingRequiredTimestamp("3.2", 1630234567890L));
    }
}
