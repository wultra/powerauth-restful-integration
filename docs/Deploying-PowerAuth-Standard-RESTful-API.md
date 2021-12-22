# Deploying PowerAuth RESTful API

This chapter explains how to deploy PowerAuth Standard RESTful API.

Enrollment Server is a Spring application (packaged as an executable WAR file) responsible for exposing the [RESTful API according to the specification](https://github.com/wultra/powerauth-crypto/blob/develop/docs/Standard-RESTful-API.md). It exposes services for end-user applications (PowerAuth Clients), such as the mobile banking app or mobile token app.

You can use this application in case you need to use PowerAuth and cannot integrate it in your own API using our integration libraries.

Detailed information about deploying Enrollment Server is available in [Enrollment Server documentation](https://github.com/wultra/enrollment-server/blob/develop/docs/Deploying-Enrollment-Server.md).
