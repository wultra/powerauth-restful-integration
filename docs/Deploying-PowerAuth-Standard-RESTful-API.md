# Deploying PowerAuth RESTful API

This chapter explains how to deploy PowerAuth Standard RESTful API.

Enrollment Server is a Spring application (packaged as an executable WAR file) responsible for exposing the [RESTful API according to the specification](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Standard-RESTful-API.md). It exposes services for end-user applications (PowerAuth Clients), such as the mobile banking app or mobile token app.

You can use this application in case you need to use PowerAuth and cannot integrate it in your own API using our integration libraries.

## Downloading Enrollment Server

You can download the latest `enrollment-server.war` at the releases page:

- https://github.com/wultra/enrollment-server/releases

_Note: The enrollment server component will need to be customized in case you need to customize the activation process. The customization is described in the tutorial [Implementing the Server-Side for Authentication in Mobile Banking Apps (SCA)](https://developers.wultra.com/products/mobile-token/2021-05/tutorials/Authentication-in-Mobile-Apps/Server-Side-Tutorial#deploying-the-enrollment-server)._

## Configuring Enrollment Server

The default implementation of Enrollment server has only one compulsory configuration parameter `powerauth.service.url` that configures the REST endpoint location of a PowerAuth Server. The default value for this property points to `localhost`:

```bash
powerauth.service.url=http://localhost:8080/powerauth-java-server/rest
```

## Setting Up Credentials

_(optional)_ In case PowerAuth Server uses a [restricted access flag in the server configuration](https://github.com/wultra/powerauth-server/blob/develop/docs/Deploying-PowerAuth-Server.md#enabling-powerauth-server-security), you need to configure credentials for the PowerAuth Standard RESTful API so that it can connect to the service:

```sh
powerauth.service.security.clientToken=
powerauth.service.security.clientSecret=
```

The credentials are stored in the `pa_integration` table.

_Note: The RESTful interface is secured using Basic HTTP Authentication (pre-emptive). For SOAP interface used in the Java EE integration, PowerAuth Server uses WS-Security, `UsernameToken` validation (plain text password)._ 

## Deploying Enrollment Server

You can deploy Enrollment Server WAR into any Java EE container.

The default configuration works best with Apache Tomcat server running on default port 8080. In this case, the deployed server is accessible on `http://localhost:8080/enrollment-server/`.

To deploy Enrollment Server to Apache Tomcat, simply copy the WAR file in your `webapps` folder or deploy it using the "Tomcat Web Application Manager" application (usually deployed on default Tomcat address `http://localhost:8080/manager`).

## Deploying Enrollment Server Outside the Container

You can also execute WAR file directly using the following command:

```bash
java -jar enrollment-server.war
```

_Note: You can overwrite the port using `-Dserver.port=8090` parameter to avoid port conflicts._
