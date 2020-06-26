# Deploying PowerAuth Standard RESTful API Bootstrap

This chapter explains how to deploy PowerAuth Standard RESTful API.

PowerAuth Standard RESTful API is a Java EE application (packaged as an executable WAR file) responsible for exposing the [RESTful API according to the specification](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Standard-RESTful-API.md). It exposes services for end-user applications (PowerAuth Clients), such as the mobile banking app or mobile token app.

You can use this application in case you need to use PowerAuth and cannot integrate it in your own API using our integration libraries.

## Downloading PowerAuth Standard RESTful API

You can download the latest `powerauth-restful-server.war` at the releases page:

- https://github.com/wultra/powerauth-restful-integration/releases

## Configuring PowerAuth Standard RESTful API

The default implementation of a PowerAuth Standard RESTful API has only one compulsory configuration parameter `powerauth.service.url` that configures the REST endpoint location of a PowerAuth Server. The default value for this property points to `localhost`:

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

## Deploying PowerAuth Standard RESTful API

You can deploy PowerAuth Standard RESTful API WAR into any Java EE container.

The default configuration works best with Apache Tomcat server running on default port 8080. In this case, the deployed server is accessible on `http://localhost:8080/powerauth-restful-server/`.

To deploy PowerAuth Standard RESTful API to Apache Tomcat, simply copy the WAR file in your `webapps` folder or deploy it using the "Tomcat Web Application Manager" application (usually deployed on default Tomcat address `http://localhost:8080/manager`).

## Deploying PowerAuth Standard RESTful API Outside the Container

You can also execute WAR file directly using the following command:

```bash
java -jar powerauth-restful-server.war
```

_Note: You can overwrite the port using `-Dserver.port=8090` parameter to avoid port conflicts._
