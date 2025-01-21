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

package com.wultra.security.powerauth.rest.api.spring.encryption;

import com.wultra.security.powerauth.crypto.lib.encryptor.ServerEncryptor;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptedRequest;
import com.wultra.security.powerauth.crypto.lib.encryptor.model.EncryptorId;
import lombok.Getter;
import lombok.Setter;

/**
 * Class used for storing data used during PowerAuth decryption and encryption. A reference to an initialized ServerEncryptor
 * is also stored so that the response can be encrypted using the same object as used for request decryption.
 */
@Getter
@Setter
public class PowerAuthEncryptorData {
    /**
     * ECIES encryption context.
     */
    private final EncryptionContext context;
    /**
     * {@link ServerEncryptor} implementation.
     */
    private ServerEncryptor serverEncryptor;
    /**
     * Encrypted request data.
     */
    private EncryptedRequest encryptedRequest;
    /**
     * Decrypted request data.
     */
    private byte[] decryptedRequest;
    /**
     * Request object
     */
    private Object requestObject;

    /**
     * Initialize encryption object from either encryption or signature HTTP header.
     *
     * @param context PowerAuth encryption context derived from either encryption or signature HTTP header.
     */
    public PowerAuthEncryptorData(EncryptionContext context) {
        this.context = context;
    }

    /**
     * Get EncryptorId depending on scope of encryption.
     * @return EncryptorId depending on scope of encryption.
     */
    public EncryptorId getEncryptorId() {
        return switch (context.getEncryptionScope()) {
            case ACTIVATION_SCOPE -> EncryptorId.ACTIVATION_SCOPE_GENERIC;
            case APPLICATION_SCOPE -> EncryptorId.APPLICATION_SCOPE_GENERIC;
        };
    }
}
