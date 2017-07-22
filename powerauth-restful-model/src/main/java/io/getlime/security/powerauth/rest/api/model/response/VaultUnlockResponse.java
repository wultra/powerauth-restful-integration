/*
 * PowerAuth integration libraries for RESTful API applications, examples and
 * related software components
 *
 * Copyright (C) 2017 Lime - HighTech Solutions s.r.o.
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
package io.getlime.security.powerauth.rest.api.model.response;

/**
 * Response object for /pa/vault/unlock end-point.
 *
 * @author Petr Dvorak
 *
 */
public class VaultUnlockResponse {

    private String activationId;
    private String encryptedVaultEncryptionKey;

    /**
     * Get activation ID
     * @return Activation ID
     */
    public String getActivationId() {
        return activationId;
    }

    /**
     * Set activation ID
     * @param activationId Activation ID
     */
    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    /**
     * Get encrypted vault encryption key (using a key derived from the master transport key).
     * @return Encrypted vault encryption key.
     */
    public String getEncryptedVaultEncryptionKey() {
        return encryptedVaultEncryptionKey;
    }

    /**
     * Set encrypted vault encryption key (using a key derived from the master transport key).
     * @param encryptedVaultEncryptionKey Encrypted vault encryption key.
     */
    public void setEncryptedVaultEncryptionKey(String encryptedVaultEncryptionKey) {
        this.encryptedVaultEncryptionKey = encryptedVaultEncryptionKey;
    }

}
