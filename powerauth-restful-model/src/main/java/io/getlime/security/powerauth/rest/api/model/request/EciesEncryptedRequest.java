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
package io.getlime.security.powerauth.rest.api.model.request;

import lombok.Data;

/**
 * Request object with data encrypted by ECIES encryption.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
@Data
public class EciesEncryptedRequest {

    /**
     * Base64 encoded ephemeral public key.
     */
    private String ephemeralPublicKey;

    /**
     * Base64 encoded encrypted data.
     */
    private String encryptedData;

    /**
     * Base64 encoded MAC of key and data.
     */
    private String mac;

    /**
     * Base64 encoded nonce for IV derivation.
     */
    private String nonce;

    /**
     * Request timestamp as unix timestamp in milliseconds.
     */
    private Long timestamp;

}
