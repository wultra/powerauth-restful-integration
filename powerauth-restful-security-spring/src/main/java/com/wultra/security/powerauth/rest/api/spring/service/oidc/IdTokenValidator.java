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
package com.wultra.security.powerauth.rest.api.spring.service.oidc;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.security.oauth2.jwt.Jwt;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Additional ID token validations.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@Slf4j
final class IdTokenValidator {

    private IdTokenValidator() {
        throw new IllegalStateException("Should not be instantiated");
    }

    static boolean isAtHashValid(final Jwt idToken, final String accessToken) {
        final String atHash = idToken.getClaimAsString("at_hash");
        return atHash == null || isAtHashValid(accessToken, atHash, idToken.getHeaders().get("alg").toString());
    }

    static boolean isNonceValid(final Jwt idToken, final String nonce) {
        return nonce.equals(idToken.getClaimAsString("nonce"));
    }

    /**
     * <ol>
     *   <li>Hash the octets of the ASCII representation of the access_token with the hash algorithm for the alg Header Parameter of the ID Token's JOSE Header. For instance, if the alg is RS256, the hash algorithm used is SHA-256.</li>
     *   <li>Take the left-most half of the hash and base64url-encode it.</li>
     *   <li>The value of at_hash in the ID Token MUST match the value produced in the previous step.</li>
     * </ol>
     *
     * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#ImplicitTokenValidation">3.2.2.9. Access Token Validation</a>
     */
    private static boolean isAtHashValid(final String accessToken, final String atHash, final String signatureAlgorithm) {
        try {
            final MessageDigest digest = MessageDigest.getInstance(mapHashAlgorithm(signatureAlgorithm));
            final byte[] hash = digest.digest(accessToken.getBytes());
            final byte[] leftHalf = new byte[hash.length / 2];
            System.arraycopy(hash, 0, leftHalf, 0, leftHalf.length);
            final String computedAtHash = Base64.getUrlEncoder().withoutPadding().encodeToString(leftHalf);
            return atHash.equals(computedAtHash);
        } catch (NoSuchAlgorithmException e) {
            logger.error("Unable to validate at_hash", e);
            return false;
        }
    }

    private static String mapHashAlgorithm(final String signatureAlgorithm) throws NoSuchAlgorithmException {
        return switch (signatureAlgorithm) {
            case JwsAlgorithms.RS256, JwsAlgorithms.ES256 -> "SHA-256";
            case JwsAlgorithms.RS384, JwsAlgorithms.ES384 -> "SHA-384";
            case JwsAlgorithms.RS512, JwsAlgorithms.ES512 -> "SHA-512";
            default -> throw new NoSuchAlgorithmException("Unsupported signature algorithm: " + signatureAlgorithm);
        };
    }
}
