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

import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.ECDSAKeyProvider;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
@Slf4j
public class OAuth2Handler {

    private TokenResponse fetchTokenResponse(final String clientId, String clientSecret, final String code) {
        // TODO rewrite to restClient
        final RestTemplate restTemplate = new RestTemplate();

        final HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        // Create a map of the key/value pairs that we want to supply in the body of the request
        final MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("grant_type", "authorization_code");
        map.add("client_id", clientId);
        map.add("client_secret", clientSecret);
        map.add("code", code);
        final String redirectUri = "TODO"; //TODO
        map.add("redirect_uri", redirectUri);

        final HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(map, headers);

        // TODO
        final String url = "TODO";
        final ResponseEntity<TokenResponse> response =
                restTemplate.exchange(url,
                        HttpMethod.POST,
                        entity,
                        TokenResponse.class);

        return response.getBody();
    }

    public static void main(String[] args) throws Exception {

        final String issuerUrl = "TODO";
        final String token = fetchIdToken(issuerUrl);

        final String nonce = "top-secret";

        final DecodedJWT decodedJWT = verifyAndDecode(token, issuerUrl, nonce);
        final String subject = decodedJWT.getSubject();
        logger.info("Got subject: {}", subject);
    }

    private static DecodedJWT verifyAndDecode(final String token, final String issuerUrl, final String nonce) {
        final String algorithmName = JWT.decode(token).getAlgorithm();
        logger.debug("Using algorithm: {}", algorithmName);
        final Algorithm algorithm = switch (algorithmName) {
            case "RS256" -> Algorithm.RSA256(createRSAKeyProvider(issuerUrl));
            case "RS384" -> Algorithm.RSA384(createRSAKeyProvider(issuerUrl));
            case "RS512" -> Algorithm.RSA512(createRSAKeyProvider(issuerUrl));
            case "ES256" -> Algorithm.ECDSA256(createECDSAKeyProvider(issuerUrl));
            case "ES384" -> Algorithm.ECDSA384(createECDSAKeyProvider(issuerUrl));
            case "ES512" -> Algorithm.ECDSA512(createECDSAKeyProvider(issuerUrl));
            default -> throw new IllegalArgumentException("Unsupported algorithm: " + algorithmName);
        };

        final JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(issuerUrl)
                .withClaim("nonce", nonce)
                .build();
        return verifier.verify(token);
    }

    private static String fetchIdToken(final String issuerUrl) {
        return "TODO";
    }

    private static ECDSAKeyProvider createECDSAKeyProvider(final String issuerUrl) {
        final JwkProvider jwkProvider = createJwkProvider(issuerUrl);

        return new ECDSAKeyProvider() {
            @Override
            public ECPublicKey getPublicKeyById(final String kid) {
                try {
                    logger.debug("Requesting public key  id: {}, {}", kid, issuerUrl);
                    return (ECPublicKey) jwkProvider.get(kid).getPublicKey();
                } catch (JwkException e) {
                    logger.error("Unable to get public key id: {}, {}", kid, issuerUrl, e);
                    return null;
                }
            }

            @Override
            public ECPrivateKey getPrivateKey() {
                return null;
            }

            @Override
            public String getPrivateKeyId() {
                return null;
            }
        };
    }

    private static RSAKeyProvider createRSAKeyProvider(final String issuerUrl) {
        final JwkProvider jwkProvider = createJwkProvider(issuerUrl);

        return new RSAKeyProvider() {
            @Override
            public RSAPublicKey getPublicKeyById(String kid) {
                try {
                    logger.debug("Requesting public key  id: {}, {}", kid, issuerUrl);
                    return (RSAPublicKey) jwkProvider.get(kid).getPublicKey();
                } catch (JwkException e) {
                    logger.error("Unable to get public key id: {}, {}", kid, issuerUrl, e);
                    return null;
                }
            }

            @Override
            public RSAPrivateKey getPrivateKey() {
                return null;
            }

            @Override
            public String getPrivateKeyId() {
                return null;
            }
        };
    }

    private static JwkProvider createJwkProvider(final String issuerUrl) {
        return new JwkProviderBuilder(issuerUrl)
                .cached(false)
                .build();
    }
}
