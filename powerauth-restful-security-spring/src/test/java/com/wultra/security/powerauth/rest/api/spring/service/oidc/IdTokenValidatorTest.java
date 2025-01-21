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

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test for {@link IdTokenValidator}.
 *
 * @author Lubos Racansky, lubos.racansky@wultra.com
 */
class IdTokenValidatorTest {

    // test vector from https://stackoverflow.com/a/36708354/204950
    private static final String ACCESS_TOKEN = "ya29.eQGmYe6H3fP_d65AY0pOMCFikA0f4hzVZGmTPPyv7k_l6HzlEIpFXnXGZjcMhkyyuqSMtN_RTGJ-xg";

    /*
    jwt.io
    {
      "sub": "1234567890",
      "name": "John Doe",
      "aud": "pas",
      "nonce": "a184d4a4sd7asd74a8sda",
      "at_hash": "lOtI0BRou0Z4LPtQuE8cCw"
    }
     */
    private static final String ID_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYXVkIjoicGFzIiwibm9uY2UiOiJhMTg0ZDRhNHNkN2FzZDc0YThzZGEiLCJhdF9oYXNoIjoibE90STBCUm91MFo0TFB0UXVFOGNDdyJ9.KZqKWSu4fD8s95E5l4Z8qqHLo5iOeu4Ks4NPMRHhhdDqszXREDrRF9nTVOiJMrYVeYnI7dPtixtL9JPyODyYAQ070Qa0bkvJ2-OTSlESgVuO62QgRXP8Ba_uN_UT_xLRKoSbgPstuv5tjHT34iugYy48Meheraoj5v-QDo8glltiWR8Bo_WOz4SrtHezD4DqKRsnE2DlTYkVqmqK8s-wgik67JhFygupSBLsmMi1zRWjThjFibWRR31kFDc1jRuUWl1RidYPHMIZkUvMT3GQWL0B45ET1-fhrpg_GQZtlLadADb24QtY06X2peyFZ3JrvYIsxf4F2R1F6UUDzDcN0g";

    private final JwtDecoder jwtDecoder = token -> {
        try {
            final SignedJWT signedJWT = SignedJWT.parse(token);
            final JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            final JWSHeader header = signedJWT.getHeader();

            return Jwt.withTokenValue(token)
                    .headers(headers -> headers.putAll(header.toJSONObject()))
                    .claims(claims -> claims.putAll(claimsSet.getClaims()))
                    .build();
        } catch (ParseException e) {
            throw new RuntimeException("Invalid token", e);
        }
    };

    @Test
    void testNonceValidator_success() {
        final Jwt jwt = jwtDecoder.decode(ID_TOKEN);

        final boolean result = IdTokenValidator.isNonceValid(jwt, "a184d4a4sd7asd74a8sda");

        assertTrue(result);
    }

    @Test
    void testNonceValidator_invalid() {
        final Jwt jwt = jwtDecoder.decode(ID_TOKEN);

        final boolean result = IdTokenValidator.isNonceValid(jwt, "invalid");

        assertFalse(result);
    }

    @Test
    void testAtHash_success() {
        final Jwt jwt = jwtDecoder.decode(ID_TOKEN);

        final boolean result = IdTokenValidator.isAtHashValid(jwt, ACCESS_TOKEN);

        assertTrue(result);
    }

    @Test
    void testAtHashValidator_invalid() {
        final Jwt jwt = jwtDecoder.decode(ID_TOKEN);

        final boolean result = IdTokenValidator.isAtHashValid(jwt, "invalid access token");

        assertFalse(result);
    }

}