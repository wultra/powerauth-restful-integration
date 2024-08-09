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
package io.getlime.security.powerauth.rest.api.spring.service.oidc;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;

/**
 * Wrap OAuth client calls, add other logic such as validation.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@Component
@AllArgsConstructor
@Slf4j
public class OAuth2Handler {

    private static final String ERROR_CODE_INVALID_TOKEN = "invalid_token";

    private final OAuth2TokenClient tokenClient;

    /**
     * Retrieve user ID from a token, using {@code authorization_code} flow. The token is verified first.
     *
     * @param request Parameter object.
     * @return User ID.
     */
    public String retrieveUserId(final OAuthActivationContext request) {
        // TODO error handling
        final TokenRequest tokenRequest = TokenRequest.builder()
                .clientId(request.getClientId())
                .code(request.getCode())
                // TODO load the application configuration
                //.clientSecret()
                //.tokenUrl()
                //.redirectUri()
                .build();
        logger.debug("Issuing token, clientId: {}", request.getClientId());
        final TokenResponse tokenResponse = tokenClient.fetchTokenResponse(tokenRequest);

        logger.debug("Token issued, verifying,  clientId: {}", request.getClientId());
        final String issuerUrl = "";
        final String audience = "";
        final Jwt jwt = verifyAndDecode(tokenResponse, issuerUrl, request.getNonce(), audience);
        return jwt.getSubject();
    }

    // TODO improve parameter object
    private Jwt verifyAndDecode(final TokenResponse tokenResponse, final String issuerUrl, final String nonce, final String audience) {
        final NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withIssuerLocation(issuerUrl)
                .jwsAlgorithms(algorithms ->
                        algorithms.addAll(List.of(
                                SignatureAlgorithm.RS256,
                                SignatureAlgorithm.RS384,
                                SignatureAlgorithm.RS512,
                                SignatureAlgorithm.ES256,
                                SignatureAlgorithm.ES384,
                                SignatureAlgorithm.ES512)))
                .build();

        final DelegatingOAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(issuerUrl),
                createAudienceValidator(audience),
                createNonceValidator(nonce),
                createAtHashValidator(tokenResponse.getAccessToken()));
        jwtDecoder.setJwtValidator(validator);
        return jwtDecoder.decode(tokenResponse.getAccessToken());
    }

    private static OAuth2TokenValidator<Jwt> createAtHashValidator(final String accessToken) {
        return idToken -> {
            final String atHash = idToken.getClaimAsString("at_hash");
            if (atHash == null || isAtHashValid(accessToken, atHash, idToken.getHeaders().get("alg").toString())) {
                return OAuth2TokenValidatorResult.success();
            }
            return OAuth2TokenValidatorResult.failure(new OAuth2Error(ERROR_CODE_INVALID_TOKEN, "The at_hash does not match", null));
        };
    }

    private static  OAuth2TokenValidator<Jwt> createNonceValidator(final String nonce) {
        return idToken -> {
            if (nonce.equals(idToken.getClaimAsString("nonce"))) {
                return OAuth2TokenValidatorResult.success();
            }
            return OAuth2TokenValidatorResult.failure(new OAuth2Error(ERROR_CODE_INVALID_TOKEN, "The nonce does not match", null));
        };
    }

    private static OAuth2TokenValidator<Jwt> createAudienceValidator(final String audience) {
        return idToken -> {
            if (idToken.getAudience().contains(audience)) {
                return OAuth2TokenValidatorResult.success();
            }
            return OAuth2TokenValidatorResult.failure(new OAuth2Error(ERROR_CODE_INVALID_TOKEN, "The required audience '%s' is missing".formatted(audience), null));
        };
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
