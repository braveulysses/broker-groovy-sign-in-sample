# broker-groovy-sign-in-sample

This sample demonstrates how a server-side web application authenticates users
through the Data Broker.

## How to run

Please note that Java 8 is required.

First, register an OAuth2 Client in the Data Broker configuration.

```
dsconfig create-key-pair --pair-name sample-idtoken-key
dsconfig create-oauth2-client --client-name Sample1 \
  --set client-id:sample1 \
  --set grant-type:authorization-code \
  --set redirect-url:http://localhost:5050/callback \
  --set id-token-signing-algorithm:rs256 \
  --set id-token-signing-key-pair:sample-idtoken-key
dsconfig create-permitted-scope --client-name Sample1 --scope-name openid
dsconfig create-permitted-scope --client-name Sample1 --scope-name email
dsconfig create-permitted-scope --client-name Sample1 --scope-name profile
```

Note the client secret that is generated.

Then, create an application configuration file.
Copy `src/ratpack/config.example.yaml` to `src/ratpack/config.yaml`
and adjust the values as appropriate.

```
# Set to false ONLY when using a test server.
strictHttpsValidation: false

authorizeEndpoint: https://example.com/oauth/authorize
tokenEndpoint: https://example.com/oauth/token
jwksEndpoint: https://example.com/jwks

clientId: test1
clientSecret: Srf9BGpgZqfu1TSI8gTFmX9in8B2Z1ox
```

Finally, the application can be started using the Gradle wrapper.
It will listen on port 5050.

```
$ ./gradlew run
:compileJava UP-TO-DATE
:compileGroovy
:processResources
:classes
:configureRun
:run
[main] INFO ratpack.server.RatpackServer - Starting server...
[main] INFO ratpack.server.RatpackServer - Building registry...
[main] INFO ratpack.server.RatpackServer - Initializing 3 services...
[ratpack-compute-1-2] INFO com.example.app.services.ConfigService - Generating application signing key
[main] INFO ratpack.server.RatpackServer - Ratpack started (development) for http://localhost:5050
```

The application currently lacks an HTML-based UI. To test, load
[http://localhost:5050/protected](http://localhost:5050/protected) in your web
browser. This endpoint will detect that you are not authenticated and redirect
you to the configured authentication server. Upon successful authentication,
you will be redirected back to the sample application. A message should
indicate that you are authenticated.

## About this sample application

This sample application is written using the [Groovy](http://groovy-lang.org)
language and the [Ratpack](https://ratpack.io) framework. These were chosen
due to their concision and readability. If you've written Java or JavaScript
before, you should find this application's source code easy to read.

## License

This is licensed under the Apache License 2.0.