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
package io.getlime.security.powerauth.app.rest.api.javaee;

import io.getlime.security.powerauth.app.rest.api.javaee.configuration.DefaultJacksonJsonProvider;
import io.getlime.security.powerauth.app.rest.api.javaee.controller.AuthenticationController;
import io.getlime.security.powerauth.app.rest.api.javaee.controller.TokenController;
import io.getlime.security.powerauth.crypto.lib.config.PowerAuthConfiguration;
import io.getlime.security.powerauth.provider.CryptoProviderUtilFactory;
import io.getlime.security.powerauth.rest.api.jaxrs.exception.*;
import io.getlime.security.powerauth.rest.api.jaxrs.filter.PowerAuthRequestFilter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;
import java.security.Security;
import java.util.HashSet;
import java.util.Set;

/**
 * PowerAuth Standard RESTful API application class.
 *
 * @author Petr Dvorak, petr@wultra.com
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

        // PowerAuth Controllers
        resources.add(AuthenticationController.class);
        resources.add(TokenController.class);
        resources.add(io.getlime.security.powerauth.app.rest.api.javaee.controller.v2.CustomActivationController.class);
        resources.add(io.getlime.security.powerauth.app.rest.api.javaee.controller.v2.EncryptedDataExchangeController.class);
        resources.add(io.getlime.security.powerauth.app.rest.api.javaee.controller.v3.CustomActivationController.class);
        resources.add(io.getlime.security.powerauth.app.rest.api.javaee.controller.v3.EncryptedDataExchangeController.class);
        resources.add(io.getlime.security.powerauth.rest.api.jaxrs.controller.v2.ActivationController.class);
        resources.add(io.getlime.security.powerauth.rest.api.jaxrs.controller.v2.SignatureController.class);
        resources.add(io.getlime.security.powerauth.rest.api.jaxrs.controller.v2.SecureVaultController.class);
        resources.add(io.getlime.security.powerauth.rest.api.jaxrs.controller.v2.TokenController.class);
        resources.add(io.getlime.security.powerauth.rest.api.jaxrs.controller.v3.ActivationController.class);
        resources.add(io.getlime.security.powerauth.rest.api.jaxrs.controller.v3.SecureVaultController.class);
        resources.add(io.getlime.security.powerauth.rest.api.jaxrs.controller.v3.SignatureController.class);
        resources.add(io.getlime.security.powerauth.rest.api.jaxrs.controller.v3.TokenController.class);
        resources.add(io.getlime.security.powerauth.rest.api.jaxrs.controller.v3.UpgradeController.class);

        // PowerAuth Exception Resolvers
        resources.add(PowerAuthActivationExceptionResolver.class);
        resources.add(PowerAuthAuthenticationExceptionResolver.class);
        resources.add(PowerAuthEncryptionExceptionResolver.class);
        resources.add(PowerAuthSecureVaultExceptionResolver.class);
        resources.add(PowerAuthUpgradeExceptionResolver.class);

        // PowerAuth Filters
        resources.add(PowerAuthRequestFilter.class);
        return resources;
    }

}
