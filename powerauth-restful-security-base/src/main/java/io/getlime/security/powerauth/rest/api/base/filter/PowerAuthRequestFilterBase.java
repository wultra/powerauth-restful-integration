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
package io.getlime.security.powerauth.rest.api.base.filter;

import com.google.common.io.BaseEncoding;
import io.getlime.security.powerauth.http.PowerAuthRequestCanonizationUtils;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URLDecoder;

/**
 * Class representing for holding any static constants available to request filters.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class PowerAuthRequestFilterBase {

    /**
     * Constant for the request attribute name "X-PowerAuth-Request-Body".
     */
    public static final String POWERAUTH_SIGNATURE_BASE_STRING = "X-PowerAuth-Request-Body";

    public static ResettableStreamHttpServletRequest filterRequest(HttpServletRequest httpRequest) throws IOException {
        ResettableStreamHttpServletRequest resettableRequest = new ResettableStreamHttpServletRequest(httpRequest);
        if (httpRequest.getMethod().toUpperCase().equals("GET")) {
            // Parse the query parameters
            String queryString = httpRequest.getQueryString();

            if (queryString != null && queryString.length() > 0) {

                // Decode the query string
                queryString = URLDecoder.decode(queryString, "UTF-8");

                // Get the canonized form
                String signatureBaseStringData = PowerAuthRequestCanonizationUtils.canonizeGetParameters(queryString);

                // Pass the signature base string as the request attribute
                if (signatureBaseStringData != null) {
                    resettableRequest.setAttribute(
                            PowerAuthRequestFilterBase.POWERAUTH_SIGNATURE_BASE_STRING,
                            BaseEncoding.base64().encode(signatureBaseStringData.getBytes("UTF-8"))
                    );
                }

            }

        } else { // ... handle POST, PUT, DELETE, ... method

            // Get the request body and pass it as the signature base string as the request attribute
            byte[] body = resettableRequest.getRequestBody();
            if (body != null) {
                resettableRequest.setAttribute(
                        PowerAuthRequestFilterBase.POWERAUTH_SIGNATURE_BASE_STRING,
                        BaseEncoding.base64().encode(body)
                );
            }
        }
        return resettableRequest;
    }

}
