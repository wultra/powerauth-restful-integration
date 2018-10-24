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
package io.getlime.security.powerauth.rest.api.spring.controller.v3;

import io.getlime.core.rest.model.base.response.Response;
import io.getlime.powerauth.soap.v3.CommitMigrationResponse;
import io.getlime.powerauth.soap.v3.StartMigrationResponse;
import io.getlime.security.powerauth.crypto.lib.enums.PowerAuthSignatureTypes;
import io.getlime.security.powerauth.http.PowerAuthEncryptionHttpHeader;
import io.getlime.security.powerauth.http.PowerAuthSignatureHttpHeader;
import io.getlime.security.powerauth.http.validator.InvalidPowerAuthHttpHeaderException;
import io.getlime.security.powerauth.http.validator.PowerAuthEncryptionHttpHeaderValidator;
import io.getlime.security.powerauth.rest.api.base.authentication.PowerAuthApiAuthentication;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthAuthenticationException;
import io.getlime.security.powerauth.rest.api.base.exception.PowerAuthMigrationException;
import io.getlime.security.powerauth.rest.api.model.request.v3.EciesEncryptedRequest;
import io.getlime.security.powerauth.rest.api.model.response.v3.EciesEncryptedResponse;
import io.getlime.security.powerauth.rest.api.spring.annotation.PowerAuth;
import io.getlime.security.powerauth.soap.spring.client.PowerAuthServiceClient;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * Controller responsible for migration.
 *
 * @author Roman Strobl, roman.strobl@wultra
 */
@RestController
@RequestMapping("/pa/v3/migration")
public class MigrationController {

    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(MigrationController.class);

    private PowerAuthServiceClient powerAuthClient;

    @Autowired
    public void setPowerAuthClient(PowerAuthServiceClient powerAuthClient) {
        this.powerAuthClient = powerAuthClient;
    }

    /**
     * Start migration of activation to version 3.
     *
     * @param request ECIES encrypted request.
     * @param encryptionHeader Encryption HTTP header.
     * @return ECIES encrypted response.
     * @throws PowerAuthMigrationException In case migration fails.
     */
    @RequestMapping(value = "start", method = RequestMethod.POST)
    public EciesEncryptedResponse migrationStart(@RequestBody EciesEncryptedRequest request,
                                                 @RequestHeader(value = PowerAuthEncryptionHttpHeader.HEADER_NAME, defaultValue = "unknown") String encryptionHeader)
            throws PowerAuthMigrationException {

        try {
            // Parse the encryption header
            PowerAuthEncryptionHttpHeader header = new PowerAuthEncryptionHttpHeader().fromValue(encryptionHeader);

            // Validate the encryption header
            try {
                PowerAuthEncryptionHttpHeaderValidator.validate(header);
            } catch (InvalidPowerAuthHttpHeaderException e) {
                throw new PowerAuthMigrationException(e.getMessage());
            }

            if (!"3.0".equals(header.getVersion())) {
                logger.warn("Endpoint does not support PowerAuth protocol version {}", header.getVersion());
                throw new PowerAuthAuthenticationException();
            }

            // Fetch data from the request
            final String ephemeralPublicKey = request.getEphemeralPublicKey();
            final String encryptedData = request.getEncryptedData();
            final String mac = request.getMac();

            // Get ECIES headers
            final String activationId = header.getActivationId();
            final String applicationKey = header.getApplicationKey();

            // Start migration on PowerAuth server
            StartMigrationResponse migrationResponse = powerAuthClient.startMigration(activationId, applicationKey, ephemeralPublicKey, encryptedData, mac);

            // Prepare a response
            final EciesEncryptedResponse response = new EciesEncryptedResponse();
            response.setMac(migrationResponse.getMac());
            response.setEncryptedData(migrationResponse.getEncryptedData());
            return response;
        } catch (Exception ex) {
            logger.warn("PowerAuth migration start failed.", ex);
            throw new PowerAuthMigrationException();
        }
    }

    /**
     * Commit migration of activation to version 3.
     *
     * @param authentication PowerAuth API authentication object.
     * @return Response.
     * @throws PowerAuthAuthenticationException In case request signature is invalid.
     * @throws PowerAuthMigrationException In case commit fails.
     */
    @RequestMapping(value = "commit", method = RequestMethod.POST)
    @PowerAuth(resourceId = "/pa/migration/commit", signatureType = {
            PowerAuthSignatureTypes.POSSESSION
    })
    public Response migrationCommit(PowerAuthApiAuthentication authentication)
            throws PowerAuthAuthenticationException, PowerAuthMigrationException {

        try {
            if (authentication == null || authentication.getActivationId() == null) {
                throw new PowerAuthAuthenticationException();
            }
            if (!"3.0".equals(authentication.getVersion())) {
                logger.warn("Endpoint does not support PowerAuth protocol version {}", authentication.getVersion());
                throw new PowerAuthAuthenticationException();
            }

            // Get signature HTTP headers
            final String activationId = authentication.getActivationId();
            final PowerAuthSignatureHttpHeader httpHeader = (PowerAuthSignatureHttpHeader) authentication.getHttpHeader();
            final String applicationKey = httpHeader.getApplicationKey();

            // Start migration on PowerAuth server
            CommitMigrationResponse migrationResponse = powerAuthClient.commitMigration(activationId, applicationKey);

            if (migrationResponse.isCommitted()) {
                return new Response();
            } else {
                throw new PowerAuthMigrationException();
            }
        } catch (PowerAuthAuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            logger.warn("PowerAuth migration commit failed.", ex);
            throw new PowerAuthMigrationException();
        }
    }
}
