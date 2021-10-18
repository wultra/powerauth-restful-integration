# Integration Libraries for Spring MVC

This tutorial shows the way mobile API developers who build their applications on top of Spring framework can integrate with PowerAuth Server.

## Prerequisites for the tutorial

- Running PowerAuth Server with available REST interface.
- Knowledge of web applications based on Spring Framework.
- Software: IDE, Application Server (Tomcat, Wildfly, ...)

## Add a Maven dependency

To add PowerAuth support in your RESTful API, add Maven dependency for PowerAuth RESTful Security module in your `pom.xml` file:

```xml
<dependency>
    <groupId>io.getlime.security</groupId>
    <artifactId>powerauth-restful-security-spring</artifactId>
    <version>${powerauth.version}</version>
</dependency>
```

## Register Bouncy Castle Provider

This step is technically required only in case your server uses end-to-end encryption, but performing it anyway will not cause any harm. First, make sure you include Bouncy Castle libraries in your dependencies:

```xml
<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcprov-jdk15on</artifactId>
    <version>${bouncycastle.version}</version>
</dependency>
```

Then, you can then register Bouncy Castle provider in your `SpringBootServletInitializer` (or an equivalent class in case you do not use Spring Boot):

```java
public class ServletInitializer extends SpringBootServletInitializer {

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {

        // Register BC provider
        Security.addProvider(new BouncyCastleProvider());

        return application.sources(PowerAuthApiJavaApplication.class);
    }

}
```

## Configure PowerAuth REST Client

<!-- begin box warning -->
Make sure to add both `io.getlime.security.powerauth` and `com.wultra.security.powerauth` packages in the `@ComponentScan` annotation. At this moment, both packages need to be scanned. We are already the process of package name migration. In the future library versions, we will only use the `com.wultra.security.powerauth`.
<!-- end -->

In order to connect to the correct PowerAuth Server, you need to add following configuration:

```java
@Configuration
@ComponentScan(basePackages = {"io.getlime.security.powerauth","com.wultra.security.powerauth"})
public class PowerAuthWebServiceConfiguration {

    @Value("${powerauth.rest.url}")
    private String powerAuthRestUrl;

    @Bean
    public PowerAuthClient powerAuthClient() {
        return new PowerAuthRestClient(powerAuthRestUrl);
    }

}
```

## Setting Up Credentials

_(optional)_ In case PowerAuth Server uses a [restricted access flag in the server configuration](https://github.com/wultra/powerauth-server/blob/develop/docs/Deploying-PowerAuth-Server.md#enabling-powerauth-server-security), you need to configure credentials for REST client:

```java
@Value("${powerauth.service.security.clientToken}")
private String clientToken;

@Value("${powerauth.service.security.clientSecret}")
private String clientSecret;

// ...

@Bean
public PowerAuthClient powerAuthClient() {
    PowerAuthRestClientConfiguration config = new PowerAuthRestClientConfiguration();
    config.setPowerAuthClientToken(clientToken);
    config.setPowerAuthClientSecret(clientSecret);
    return new PowerAuthRestClient(powerAuthRestUrl, config);
}
```

## Advanced PowerAuth REST Client Configuration

The following REST client options are available:

- `maxMemorySize` - configures maximum memory size per request, default 1 MB
- `connectTimeout` - configures connection timeout, default 5000 ms
- `proxyEnabled` - enables proxy, disabled by default
- `proxyHost` - proxy hostname or IP address
- `proxyPort` - proxy server port
- `proxyUsername` - proxy username in case proxy authentication is required
- `proxyPassword` - proxy password in case proxy authentication is required
- `powerAuthClientToken` - client token for PowerAuth server authentication, used in case authentication is enabled on PowerAuth server
- `powerAuthClientSecret` - client secret for PowerAuth server authentication, used in case authentication is enabled on PowerAuth server
- `acceptInvalidSslCertificate` - whether SSL certificates should be validated, used during development

## Register PowerAuth Components

As a part of the PowerAuth integration setup, you need to register following components by registering appropriate `@Beans` and by adding these components to the Spring life-cycle in your `WebMvcConfigurer`:

```java
@Configuration
public class WebApplicationConfig implements WebMvcConfigurer {

    @Bean
    public PowerAuthWebArgumentResolver powerAuthWebArgumentResolver() {
        return new PowerAuthWebArgumentResolver();
    }

    @Bean
    public PowerAuthEncryptionArgumentResolver powerAuthEncryptionArgumentResolver() {
        return new PowerAuthEncryptionArgumentResolver();
    }

    @Bean
    public PowerAuthAnnotationInterceptor powerAuthInterceptor() {
        return new PowerAuthAnnotationInterceptor();
    }

    @Bean
    public FilterRegistrationBean powerAuthFilterRegistration() {
        FilterRegistrationBean<PowerAuthRequestFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new PowerAuthRequestFilter());
        registrationBean.setMatchAfter(true);
        return registrationBean;
    }

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
        argumentResolvers.add(powerAuthWebArgumentResolver());
        argumentResolvers.add(powerAuthEncryptionArgumentResolver());
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(powerAuthInterceptor());
    }

}
```

`PowerAuthWebArgumentResolver` bean is responsible for auto-injecting PowerAuth authentication objects into the controller handler methods (see example in [Verify Signatures Chapter](#verify-signatures)). You need to add it to argument resolver list.

`PowerAuthEncryptionArgumentResolver` bean is responsible for auto-injecting PowerAuth encryption objects into the controller handler methods (see example in [Use End-to-End Encryption Chapter](#use-end-to-end-encryption)). You need to add it to argument resolver list.

`PowerAuthInterceptor` bean is responsible for the `@PowerAuth` annotation handling (see example in [Verify Signatures Chapter](#verify-signatures)). You need to add it to the interceptor registry.

Finally, the `FilterRegistrationBean` (with the `PowerAuthRequestFilter` filter) is a technical component that passes the HTTP request body as an attribute of `HttpServletRequest`, so that it can be used for signature validation.

### Register a PowerAuth Application Configuration

_(optional)_

PowerAuth uses the concept of `application ID` and `application secret`. While `applicationId` attribute is transmitted with requests in `X-PowerAuth-Authorization` header, `applicationSecret` is shared implicitly between the client and server and is a part of the actual signature value. Applications are a first class citizen in PowerAuth protocol. Intermediate application, however, may influence which applications are accepted by implementing following configuration.

```java
@Configuration
public class ApplicationConfiguration implements PowerAuthApplicationConfiguration {

    @Override
    public Map<String, Object> statusServiceCustomObject() {
        return null; // suggested default implementation
    }

}
```

### Set Up Spring Security

_(optional)_

Create a security configuration class `SecurityConfig` extending `WebSecurityConfigurerAdapter`. The configuration we will use:

- disable default Basic HTTP authentication
- disables CSRF (we don't need it for REST)
- register your authentication entry point (if someone tries to visit our API without prior authentication, show error)
- secures all REST endpoints with `/secured/` prefix


```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private PowerAuthApiAuthenticationEntryPoint apiAuthenticationEntryPoint;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/secured/**").fullyAuthenticated();
        http.httpBasic().disable();
        http.csrf().disable();
        http.exceptionHandling().authenticationEntryPoint(apiAuthenticationEntryPoint);
    }

}
```

### Verify Signatures

This sample `@Controller` implementation illustrates how to use `@PowerAuth` annotation to verify that the request signature matches what is expected - in this case, to establish an authenticated session. In case the authentication is not successful, the `PowerAuthApiAuthentication` object is `null`. You may check for the `null` value and raise `PowerAuthAuthenticationException` that is handled alongside other application exceptions via default `@ControllerAdvice`.

<!-- begin box info -->
Note: Controllers that establish a session must not be on a context that is protected by Spring Security (for example `/secured/`, in our example), otherwise context could never be reached and session will never be established.
<!-- end -->

```java
@Controller
@RequestMapping(value = "session")
public class AuthenticationController {

    @RequestMapping(value = "login", method = RequestMethod.POST)
    @PowerAuth(resourceId = "/session/login")
    @ResponseBody
    public MyApiResponse login(PowerAuthApiAuthentication auth) {
        if (auth == null) {
            // handle authentication failure
            throw new PowerAuthSignatureInvalidException();
        }
        // use userId if needed ...
        final String userId = auth.getUserId();

        // create authenticated session
        SecurityContextHolder.getContext().setAuthentication((Authentication) auth);

        // return OK response
        return new MyApiResponse(Status.OK, userId);
    }

}
```

The `resourceId` parameter of the `@PowerAuth` annotation can substitute placeholders (marked via "${placeholder}") with the actual parameters of the handler method. Mobile client can construct resource ID values in a dynamic way accordingly. The implementation takes into account all handler method parameters that are annotated via `@RequestParam` or `@PathVariable` annotations and extracts values from the request parameter map.

<!-- begin box info -->
In case both `@RequestParam` and `@PathVariable` with the same name exist, the value of `@RequestParam` takes precedence. This is because `@RequestParam` usually maps to the HTTP GET query parameter that cannot be easily changed in existing API, while `@PathVariable` is just a URL placeholder that can be renamed in the code with no impact on functionality.
<!-- end -->

Example of using dynamic resource ID:

```java
@Controller
@RequestMapping(value = "secured")
public class AuthenticationController {

    @RequestMapping(value = "account/{id}", method = RequestMethod.POST)
    @PowerAuth(resourceId = "/secured/account/${id}?filter=${filter}")
    @ResponseBody
    public MyAccountApiResponse changeAccountSettings(
            @PathVariable("id") String accountId, @RequestParam("filter") String filter,  PowerAuthApiAuthentication auth) {
        
        if (auth == null) {
            // handle authentication failure
            throw new PowerAuthSignatureInvalidException();
        }
        
        // use userId for business logic ...
        final String userId = auth.getUserId();
        final Account account = myService.updateAccount(accountId, userId, filter);
        
        // return OK response
        return new MyAccountApiResponse(Status.OK, userId);
    }

}
```

In case you need a more low-level access to the signature verification, you can verify the signature manually using the `PowerAuthAuthenticationProvider` like this:

```java
@Controller
@RequestMapping(value = "session")
public class AuthenticationController {

    @Autowired
    private PowerAuthAuthenticationProvider authenticationProvider;

    @RequestMapping(value = "login", method = RequestMethod.POST)
    @ResponseBody
    public PowerAuthAPIResponse<String> login(
            @RequestHeader(value = PowerAuthSignatureHttpHeader.HEADER_NAME, required = true) String signatureHeader,
            HttpServletRequest servletRequest) throws Exception {

        final PowerAuthApiAuthentication apiAuthentication = authenticationProvider.validateRequestSignature(
            "POST",
            "Any data".getBytes(StandardCharsets.UTF_8),
            "/session/login",
            signatureHeader
        );

        if (apiAuthentication == null || apiAuthentication.getUserId() == null) {
            throw new PowerAuthSignatureInvalidException();
        }
        SecurityContextHolder.getContext().setAuthentication((Authentication) apiAuthentication);
        return new PowerAuthAPIResponse<String>("OK", "User " + userId);
    }

}
```

### Use Token Based Authentication

This sample `@Controller` implementation illustrates how to use `@PowerAuthToken` annotation to verify simple token based authentication headers. In case the authentication is not successful, the `PowerAuthApiAuthentication` object is null.

Please note that token based authentication should be used only for endpoints with lower sensitivity, such as simplified account information for widgets or smart watch, that are also not prone to replay attack.

```java
@Controller
@RequestMapping(value = "secure/account")
public class AuthenticationController {

    @Autowired
    private CustomService service;

    @RequestMapping(value = "widget/balance", method = RequestMethod.GET)
    @PowerAuthToken
    public @ResponseBody PowerAuthAPIResponse<String> getBalance(PowerAuthApiAuthentication apiAuthentication) throws PowerAuthAuthenticationException {
        if (apiAuthentication == null) {
            throw new PowerAuthTokenInvalidException();
        } else {
            String userId = apiAuthentication.getUserId();
            String balance = service.getBalanceForUser(userId);
            return new PowerAuthAPIResponse<String>("OK", balance);
        }
    }

}
```

## Use End-To-End Encryption

You can use end-to-end encryption to add additional encryption layer on top of the basic HTTPS encryption to protect the request body contents better.

End-to-end encryption provided by PowerAuth uses `POST` method for all data transport, and it requires a predefined request / response structure.

### Encryption in Application Scope

You can encrypt data in `application` scope (non-personalized) using following pattern:

```java
@RestController
@RequestMapping(value = "/exchange")
public class EncryptedDataExchangeController {

    @RequestMapping(value = "application", method = RequestMethod.POST)
    @PowerAuthEncryption(scope = EciesScope.APPLICATION_SCOPE)
    public DataExchangeResponse exchangeInApplicationScope(@EncryptedRequestBody DataExchangeRequest request,
                                             EciesEncryptionContext eciesContext) throws PowerAuthEncryptionException {

        if (eciesContext == null) {
            throw new PowerAuthEncryptionException();
        }

        // Return a slightly different String containing original data in response
        return new DataExchangeResponse("Server successfully decrypted signed data: " + (request == null ? "''" : request.getData()) + ", scope: " + eciesContext.getEciesScope());
    }
}
```

The method argument annotated by the `@EncryptedRequestBody` annotation is set with decrypted request data. The data is decrypted using an ECIES decryptor initialized in `application` scope.

The response data is automatically encrypted using the previously created an ECIES decryptor which was used for decrypting the request data.

### Encryption in Activation Scope

You can encrypt data in `activation` scope (personalized) using following pattern:

```java
@RestController
@RequestMapping(value = "/exchange")
public class EncryptedDataExchangeController {

    @RequestMapping(value = "activation", method = RequestMethod.POST)
    @PowerAuthEncryption(scope = EciesScope.ACTIVATION_SCOPE)
    public DataExchangeResponse exchangeInActivationScope(@EncryptedRequestBody DataExchangeRequest request,
                                            EciesEncryptionContext eciesContext) throws PowerAuthEncryptionException {

        if (eciesContext == null) {
            throw new PowerAuthEncryptionException();
        }

        // Return a slightly different String containing original data in response
        return new DataExchangeResponse("Server successfully decrypted signed data: " + (request == null ? "''" : request.getData()) + ", scope: " + eciesContext.getEciesScope());
    }
}
```

The method argument annotated by the `@EncryptedRequestBody` annotation is set with decrypted request data. The data is decrypted using an ECIES decryptor initialized in `activation` scope.

The response data is automatically encrypted using the previously created an ECIES decryptor which was used for decrypting the request data.

### Signed and Encrypted Requests

You can also sign the data before encryption and perform signature verification of decrypted data using following pattern:

```java
@RestController
@RequestMapping(value = "/exchange")
public class EncryptedDataExchangeController {

    @RequestMapping(value = "signed", method = RequestMethod.POST)
    @PowerAuth(resourceId = "/exchange/signed")
    @PowerAuthEncryption(scope = EciesScope.ACTIVATION_SCOPE)
    public DataExchangeResponse exchangeSignedAndEncryptedData(@EncryptedRequestBody DataExchangeRequest request,
                                                                EciesEncryptionContext eciesContext,
                                                                PowerAuthApiAuthentication auth) throws PowerAuthAuthenticationException, PowerAuthEncryptionException {

        if (auth == null || auth.getUserId() == null) {
            throw new PowerAuthSignatureInvalidException();
        }

        if (eciesContext == null) {
            throw new PowerAuthEncryptionException();
        }

        // Return a slightly different String containing original data in response
        return new DataExchangeResponse("Server successfully decrypted data and verified signature, request data: " + (request == null ? "''" : request.getData()) + ", user ID: " + auth.getUserId());
    }

}
```

The method argument annotated by the `@EncryptedRequestBody` annotation is set with decrypted request data. The data is decrypted using an ECIES decryptor initialized in `activation` scope. The signature received in PowerAuth HTTP signature header is verified.

The response data is automatically encrypted using the previously created an ECIES decryptor which was used for decrypting the request data.

<!-- begin box info -->
Note: You can use `String` or `byte[]` data types instead of using request/response objects for encryption of raw data.
<!-- end -->
