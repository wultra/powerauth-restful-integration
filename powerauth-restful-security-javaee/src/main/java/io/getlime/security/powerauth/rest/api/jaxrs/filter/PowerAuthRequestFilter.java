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

package io.getlime.security.powerauth.rest.api.jaxrs.filter;

import io.getlime.security.powerauth.rest.api.base.filter.PowerAuthRequestFilterBase;
import io.getlime.security.powerauth.rest.api.base.filter.ResettableStreamHttpServletRequest;

import javax.annotation.Priority;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Context;
import javax.ws.rs.ext.Provider;
import java.io.IOException;

/**
 * Request filter that intercepts the request body, forwards it to the controller 
 * as a request attribute named "X-PowerAuth-Request-Body" and resets the stream.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 *
 */
@Provider
@Priority(Priorities.AUTHENTICATION)
public class PowerAuthRequestFilter implements ContainerRequestFilter {

    @Context
    private HttpServletRequest httpRequest;

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        // WORKAROUND: fix issues with @FormParam annotations
        httpRequest.getParameterMap();

        final ResettableStreamHttpServletRequest httpServletRequest = PowerAuthRequestFilterBase.filterRequest(httpRequest);
        requestContext.setEntityStream(httpServletRequest.getInputStream());
    }

}
