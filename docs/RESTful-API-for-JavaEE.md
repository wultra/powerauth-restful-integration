# Integration Libraries for Java EE (JAX-RS)

This tutorial shows the way mobile API developers who build their applications with JAX-RS integrate with PowerAuth Server.

## Prerequisites for the tutorial

- Running PowerAuth Server with available SOAP interface.
- Knowledge of Java EE applications based on JAX-RS.
- Software: IDE - Spring Tool Suite, Java EE Application Server (Pivotal Server, Tomcat, ...)

## Add Maven Dependency

To add PowerAuth support in your RESTful API, add Maven dependency for PowerAuth RESTful Security module in your `pom.xml` file:

```xml
<dependency>
    <groupId>io.getlime.security</groupId>
    <artifactId>powerauth-restful-security-javaee</artifactId>
    <version>${powerauth.version}</version>
</dependency>
```

## Register Bouncy Castle Provider

This step is technically required only in case your server uses end-to-end encryption, but performing it anyway will not cause any harm. First, make sure you include Bouncy Castle libraries in your dependencies:

```xml
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcprov-ext-jdk15on</artifactId>
    <version>${bouncycastle.version}</version>
</dependency>
```

Then, you can then register Bouncy Castle provider in your `Application` class (or an equivalent class in case you use Jersey or some similar technology):

```java
@ApplicationPath("/")
public class JavaEEApplication extends Application {

    public JavaEEApplication() {
        super();

        // Register BC provider
        Security.addProvider(new BouncyCastleProvider());

        // Tell PowerAuth components to use BC provider
        PowerAuthConfiguration.INSTANCE.setKeyConvertor(CryptoProviderUtilFactory.getCryptoProviderUtils());
    }

    @Override
    public Set<Class<?>> getClasses() {
        // ... see more information below
        return resources;
    }
}
```

## Produce Required Beans

In order to connect to the correct PowerAuth Server, you need to add a producer that configures SOAP service endpoint and default application configuration.

```java
@Dependent
public class PowerAuthBeanFactory {

    @Produces
    public PowerAuthServiceClient buildClient() {
        try {
            return new PowerAuthServiceClient("http://localhost:8080/powerauth-java-server/soap");
        } catch (AxisFault axisFault) {
            return null;
        }
    }

    @Produces
    public PowerAuthApplicationConfiguration buildApplicationConfiguration() {
        return new DefaultApplicationConfiguration();
    }

}
```

## Setting Up Credentials

// TODO: Describe SOAP client WS-Security configuration

_Note: For SOAP interface, PowerAuth Server uses WS-Security, `UsernameToken` validation (plain text password). The RESTful interface is secured using Basic HTTP Authentication (pre-emptive)._

## Register Resources

In order to automatically use resources, exception resolvers and filters, you need to register them in your application. For plain JAX-RS application, this is how to do it:

```java
@ApplicationPath("/")
public class JavaEEApplication extends Application {

    @Override
    public Set<Class<?>> getClasses() {
        Set<Class<?>> resources = new HashSet<>();

        // Your resources
        // ...
        // ...

        // PowerAuth Controllers
        resources.add(io.getlime.security.powerauth.rest.api.jaxrs.controller.v3.ActivationController.class);
        resources.add(io.getlime.security.powerauth.rest.api.jaxrs.controller.v3.SecureVaultController.class);
        resources.add(io.getlime.security.powerauth.rest.api.jaxrs.controller.v3.SignatureController.class);
        resources.add(io.getlime.security.powerauth.rest.api.jaxrs.controller.v3.TokenController.class);
        resources.add(io.getlime.security.powerauth.rest.api.jaxrs.controller.v3.UpgradeController.class);
        resources.add(io.getlime.security.powerauth.rest.api.jaxrs.controller.v3.RecoveryController.class);
        
        // PowerAuth Exception Resolvers
        resources.add(PowerAuthActivationExceptionResolver.class);
        resources.add(PowerAuthRecoveryExceptionResolver.class);
        resources.add(PowerAuthAuthenticationExceptionResolver.class);
        resources.add(PowerAuthEncryptionExceptionResolver.class);
        resources.add(PowerAuthSecureVaultExceptionResolver.class);
        resources.add(PowerAuthUpgradeExceptionResolver.class);
        
        // PowerAuth Filters
        resources.add(PowerAuthRequestFilter.class);

        return resources;
    }

}
```

In case you still need to use legacy `v2` controllers, you can also register these controllers:
```java
        resources.add(io.getlime.security.powerauth.rest.api.jaxrs.controller.v2.ActivationController.class);
        resources.add(io.getlime.security.powerauth.rest.api.jaxrs.controller.v2.SignatureController.class);
        resources.add(io.getlime.security.powerauth.rest.api.jaxrs.controller.v2.SecureVaultController.class);
        resources.add(io.getlime.security.powerauth.rest.api.jaxrs.controller.v2.TokenController.class);
```


Note that Jersey uses `ResourceConfig` subclass for a similar purpose...

## Custom PowerAuth Application Configuration

_(optional)_

PowerAuth uses the concept of `application ID` and `application secret`. While `applicationId` attribute is transmitted with requests in `X-PowerAuth-Authorization` header, `applicationSecret` is shared implicitly between client and server and is a part of the actual signature value. Applications are a first class citizen in PowerAuth protocol. Intermediate application, however, may influence which applications are accepted by implementing following configuration.

```java
public class ApplicationConfiguration implements PowerAuthApplicationConfiguration {

  @Override
  public boolean isAllowedApplicationKey(String applicationKey) {
    return true; // default implementation
  }

  @Override
  public Map<String, Object> statusServiceCustomObject() {
    return null; // default implementation
  }

}
```

You can then return instance of this class in the producer method mentioned above, instead of `DefaultApplicationConfiguration` instance.

## Validate Signatures

In order to validate request signatures, you need to:

- inject a `HttpServletRequest` instance using the `@Context` annotation
- inject a `PowerAuthAuthenticationProvider` instance
- add `@HeaderParam(value = PowerAuthSignatureHttpHeader.HEADER_NAME) String authHeader` in resource methods

Then, you can process the header and request using the authentication provider.

Here is the source code example:

```java
@Path("pa/signature")
@Produces(MediaType.APPLICATION_JSON)
public class AuthenticationController {

    @Context
    private HttpServletRequest request;

    @Inject
    private PowerAuthAuthenticationProvider authenticationProvider;

    @POST
    @Path("validate")
    @Consumes("*/*")
    @Produces(MediaType.APPLICATION_JSON)
    public PowerAuthApiResponse<String> login(String body, @HeaderParam(value = PowerAuthSignatureHttpHeader.HEADER_NAME) String authHeader) throws PowerAuthAuthenticationException {

        // ##EXAMPLE: Here, we could store the authentication in the session like this:
        // ##EXAMPLE: SecurityContextHolder.getContext().setAuthentication(apiAuthentication);
        // ##EXAMPLE: ... or you can grab a user ID like this and use it for querying back-end:
        // ##EXAMPLE: String userId = apiAuthentication.getUserId();

        PowerAuthApiAuthentication auth = authenticationProvider.validateRequestSignature(
                request,
                "/pa/signature/validate",
                authHeader
        );

        if (auth != null && auth.getUserId() != null) {
            return new PowerAuthApiResponse<>("OK", "Hooray! User: " + auth.getUserId());
        } else {
            return new PowerAuthApiResponse<>("ERROR", "Authentication failed.");
        }

    }
}
```

### Use Token Based Authentication

This sample resource implementation illustrates how to use simple token based authentication. In case the authentication is not successful, the `PowerAuthApiAuthentication` object is null.

Please note that token based authentication should be used only for endpoints with lower sensitivity, such as simplified account information for widgets or smart watch, that are also not prone to replay attack.

```java
@Path("secure/account")
@Produces(MediaType.APPLICATION_JSON)
public class AuthenticationController {

    @Inject
    private PowerAuthAuthenticationProvider authenticationProvider;

    @Inject
    private CustomService service;

    @POST
    @Path("widget/balance")
    @Consumes("*/*")
    @Produces(MediaType.APPLICATION_JSON)
    public PowerAuthApiResponse<String> getBalance(@HeaderParam(value = PowerAuthTokenHttpHeader.HEADER_NAME) String tokenHeader) throws PowerAuthAuthenticationException {
        PowerAuthApiAuthentication auth = authenticationProvider.validateToken(tokenHeader);
        if (apiAuthentication == null) {
            throw new PowerAuthAuthenticationException();
        } else {
            String userId = apiAuthentication.getUserId();
            String balance = service.getBalanceForUser(userId);
            return new PowerAuthAPIResponse<String>("OK", balance);
        }
    }

}
```

## Use End-To-End Encryption

You can use end-to-end encryption to add an additional encryption layer on top of the basic HTTPS encryption to protect the request body contents better.

End-to-end encryption provided by PowerAuth uses `POST` method for all data transport and it requires predefined request / response structure.

### Encryption in Application Scope

You can encrypt data in `application` scope (non-personalized) using following pattern:
 
```java
@Path("/exchange")
@Produces(MediaType.APPLICATION_JSON)
public class EncryptedDataExchangeController {

    @Inject
    private PowerAuthEncryptionProvider encryptionProvider;

    @POST
    @Path("application")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public EciesEncryptedResponse exchangeInApplicationScope() throws PowerAuthEncryptionException {
        // Decrypt request
        PowerAuthEciesEncryption<DataExchangeRequest> eciesEncryption = encryptionProvider.decryptRequest(httpServletRequest,
                DataExchangeRequest.class, EciesScope.APPLICATION_SCOPE);
        DataExchangeRequest request = eciesEncryption.getRequestObject();
        EciesEncryptionContext eciesContext = eciesEncryption.getContext();

        if (eciesContext == null) {
            throw new PowerAuthEncryptionException("Decryption failed");
        }

        // Prepare response object
        DataExchangeResponse exchangeResponse = new DataExchangeResponse("Server successfully decrypted signed data: " + (request == null ? "''" : request.getData()) + ", scope: " + eciesContext.getEciesScope());

        // Encrypt response
        return encryptionProvider.encryptResponse(exchangeResponse, eciesEncryption);
    }
}
```

The encryption provider decrypts the request data using ECIES decryptor in `application` scope. In case the decryption succeeds, a response object is created and encrypted using previously created ECIES decryptor.

### Encryption in Activation Scope

You can encrypt data in `activation` scope (personalized) using following pattern:
 
```java
@Path("/exchange")
@Produces(MediaType.APPLICATION_JSON)
public class EncryptedDataExchangeController {

    @Inject
    private PowerAuthEncryptionProvider encryptionProvider;
    
    @POST
    @Path("activation")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public EciesEncryptedResponse exchangeInActivationScope() throws PowerAuthEncryptionException {
        // Decrypt request
        PowerAuthEciesEncryption<DataExchangeRequest> eciesEncryption = encryptionProvider.decryptRequest(httpServletRequest,
                    DataExchangeRequest.class, EciesScope.ACTIVATION_SCOPE);
        DataExchangeRequest request = eciesEncryption.getRequestObject();
        EciesEncryptionContext eciesContext = eciesEncryption.getContext();
    
        if (eciesContext == null) {
            throw new PowerAuthEncryptionException("Decryption failed");
        }
    
        // Prepare response object
        DataExchangeResponse exchangeResponse = new DataExchangeResponse("Server successfully decrypted signed data: " + (request == null ? "''" : request.getData()) + ", scope: " + eciesContext.getEciesScope());
    
        // Encrypt response
        return encryptionProvider.encryptResponse(exchangeResponse, eciesEncryption);
    }
}
``` 

The encryption provider decrypts the request data using ECIES decryptor in `activation` scope. In case the decryption succeeds, a response object is created and encrypted using previously created ECIES decryptor.

### Signed and Encrypted Requests

You can also sign the data before encryption and perform signature verification of decrypted data using following pattern:

```java
@RestController
@RequestMapping(value = "/exchange")
public class EncryptedDataExchangeController {

    @Inject
    private PowerAuthEncryptionProvider encryptionProvider;
    
    @Inject
    private PowerAuthAuthenticationProvider authenticationProvider;

    @POST
    @Path("signed")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public EciesEncryptedResponse exchangeSignedAndEncryptedData(@HeaderParam(value = PowerAuthSignatureHttpHeader.HEADER_NAME) String authHeader) throws PowerAuthEncryptionException, PowerAuthAuthenticationException {
        // Decrypt request
        PowerAuthEciesEncryption<DataExchangeRequest> eciesEncryption = encryptionProvider.decryptRequest(httpServletRequest,
                    DataExchangeRequest.class, EciesScope.ACTIVATION_SCOPE);
        DataExchangeRequest request = eciesEncryption.getRequestObject();
    
        if (eciesEncryption.getContext() == null) {
            throw new PowerAuthEncryptionException("Decryption failed");
        }
    
        // Verify PowerAuth signature
        PowerAuthApiAuthentication auth = authenticationProvider.validateRequestSignature(
                    httpServletRequest,
                    "/exchange/signed",
                    authHeader
        );
                
        if (auth != null && auth.getUserId() != null) {
            // Prepare response object
            DataExchangeResponse exchangeResponse = new DataExchangeResponse("Server successfully decrypted data and verified signature, request data: " + (request == null ? "''" : request.getData()) + ", user ID: " + auth.getUserId());
    
            // Encrypt response
            return encryptionProvider.encryptResponse(exchangeResponse, eciesEncryption);
        } else {
            throw new PowerAuthAuthenticationException("Authentication failed.");
        }
    }
}
```

The encryption provider decrypts the request data using ECIES decryptor in `activation` scope. In case the decryption succeeds, the signature received in PowerAuth HTTP signature header is verified. 
If the signature verification succeeds a response is encrypted using previously created ECIES decryptor.

_Note: You can also use `String` or `byte[]` data types instead of using request/response objects for encryption of raw data._

### Non-Personalized End-To-End Encryption (v2 - legacy)

To use legacy non-personalized (application specific) encryption, use following pattern:

```java
@Path("pa/custom/activation")
@Produces(MediaType.APPLICATION_JSON)
public class EncryptedController {

    @Inject
    private EncryptorFactory encryptorFactory;

    @POST
    @Path("create")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public PowerAuthApiResponse<NonPersonalizedEncryptedPayloadModel> createNewActivation( PowerAuthApiRequest<NonPersonalizedEncryptedPayloadModel> encryptedRequest) throws PowerAuthActivationException {
        try {

            // Prepare an encryptor
            final PowerAuthNonPersonalizedEncryptor encryptor = encryptorFactory.buildNonPersonalizedEncryptor(encryptedRequest);
            if (encryptor == null) {
                throw new EncryptionException("Unable to initialize encryptor.");
            }

            // Decrypt the request object
            OriginalRequest request = encryptor.decrypt(object, OriginalRequest.class);

            if (request == null) {
                throw new EncryptionException("Unable to decrypt request object.");
            }

            // ... do your business logic with OriginalRequest instance

            // Create original response object
            OriginalResponse response = new OriginalResponse();
            response.setAttribute1("attribute1");
            response.setAttribute2("attribute2");
            response.setAttribute3("attribute3");

            // Encrypt response object
            final PowerAuthApiResponse<NonPersonalizedEncryptedPayloadModel> encryptedResponse = encryptor.encrypt(response);

            if (encryptedResponse == null) {
                throw new EncryptionException("Unable to encrypt response object.");
            }

            // Return response
            return encryptedResponse;

        } catch (IOException e) {
            throw new PowerAuthActivationException();
        }

    }

}
```
