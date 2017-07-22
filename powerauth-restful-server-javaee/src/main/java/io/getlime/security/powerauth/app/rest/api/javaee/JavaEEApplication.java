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

package io.getlime.security.powerauth.app.rest.api.javaee;

import io.getlime.security.powerauth.app.rest.api.javaee.configuration.DefaultJacksonJsonProvider;
import io.getlime.security.powerauth.app.rest.api.javaee.controller.AuthenticationController;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.provider.CryptoProviderUtilFactory;
import io.getlime.security.powerauth.rest.api.jaxrs.controller.ActivationController;
import io.getlime.security.powerauth.rest.api.jaxrs.controller.SecureVaultController;
import io.getlime.security.powerauth.rest.api.jaxrs.exception.PowerAuthActivationExceptionResolver;
import io.getlime.security.powerauth.rest.api.jaxrs.exception.PowerAuthAuthenticationExceptionResolver;
import io.getlime.security.powerauth.rest.api.jaxrs.exception.PowerAuthSecureVaultExceptionResolver;
import io.getlime.security.powerauth.rest.api.jaxrs.filter.PowerAuthRequestFilter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;
import java.security.Security;
import java.util.HashSet;
import java.util.Set;

/**
 * PowerAuth 2.0 Standard RESTful API application class.
 *
 * @author Petr Dvorak, petr@lime-company.eu
 */
@ApplicationPath("/")
public class JavaEEApplication extends Application {

    public JavaEEApplication() {
        super();
        Security.addProvider(new BouncyCastleProvider());
        PowerAuthConfiguration.INSTANCE.setKeyConvertor(CryptoProviderUtilFactory.getCryptoProviderUtils());
    }

    @Override
    public Set<Class<?>> getClasses() {
        Set<Class<?>> resources = new HashSet<>();

        // Jackson
        resources.add(DefaultJacksonJsonProvider.class);

        // PowerAuth 2.0 Controllers
        resources.add(AuthenticationController.class);
        resources.add(ActivationController.class);
        resources.add(SecureVaultController.class);

        // PowerAuth 2.0 Exception Resolvers
        resources.add(PowerAuthActivationExceptionResolver.class);
        resources.add(PowerAuthAuthenticationExceptionResolver.class);
        resources.add(PowerAuthSecureVaultExceptionResolver.class);

        // PowerAuth 2.0 Filters
        resources.add(PowerAuthRequestFilter.class);
        return resources;
    }

}
