/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2024 Wultra s.r.o.
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
package io.getlime.security.powerauth.rest.api.spring.encryption;

import lombok.Builder;
import lombok.Data;
import lombok.ToString;

/**
 * Class encapsulating the ECIES encryption request parameters.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Data
@Builder
public class EncryptionRequest {

    /**
     * Activation ID. Specified in case of activation scope.
     */
    private String activationId;

    /**
     * Application key. Specified in case of application scope.
     */
    private String applicationKey;

    /**
     * Ephemeral public key encoded in Base64.
     */
    private String ephemeralPublicKey;

    /**
     * Nonce encoded in Base64.
     */
    @ToString.Exclude
    private String nonce;

    /**
     * Protocol version.
     */
    private String protocolVersion;

    /**
     * Unix timestamp as milliseconds.
     */
    private Long timestamp;

}
