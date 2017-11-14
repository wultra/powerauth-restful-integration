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

package io.getlime.security.powerauth.rest.api.model.entity;

/**
 * Class representing original payload of the encrypted response for the /pa/token endpoint.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
public class TokenResponsePayload {

    private String tokenId;
    private String tokenSecret;
    private String expires;

    /**
     * Get token ID.
     * @return Token ID.
     */
    public String getTokenId() {
        return tokenId;
    }

    /**
     * Set token ID.
     * @param tokenId Token ID.
     */
    public void setTokenId(String tokenId) {
        this.tokenId = tokenId;
    }

    /**
     * Get token secret.
     * @return Token secret.
     */
    public String getTokenSecret() {
        return tokenSecret;
    }

    /**
     * Set token secret.
     * @param tokenSecret Token secret.
     */
    public void setTokenSecret(String tokenSecret) {
        this.tokenSecret = tokenSecret;
    }

    /**
     * Timestamp when the token expires, date and time encoded as ISO8601 format.
     * @return Expiration timestamp.
     */
    public String getExpires() {
        return expires;
    }

    /**
     * Timestamp when the token expires, date and time encoded as ISO8601 format.
     * @param expires Expiration timestamp.
     */
    public void setExpires(String expires) {
        this.expires = expires;
    }
}
