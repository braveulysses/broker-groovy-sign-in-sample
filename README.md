# broker-groovy-sign-in-sample [![Build Status](https://travis-ci.org/UnboundID/broker-groovy-sign-in-sample.svg?branch=master)](https://travis-ci.org/UnboundID/broker-groovy-sign-in-sample)

This sample demonstrates how a server-side web application can use the Data
Broker as an authentication and authorization server using OpenID Connect.

## How to run

Please note that Java 8 is required. The Data Broker must be version 6.0.0.0
and above, and the "user and reference apps" starter schema must have been
installed.

First, register an OAuth2 Client in the Data Broker configuration.
The `setup.dsconfig` file is provided for this purpose.

```
dsconfig --no-prompt --batch-file setup.dsconfig
```

Note that a client secret will be generated automatically, and it is needed in
the next step. You can use a command like the following to obtain the generated
client secret, or you can find it using the Management Console.

```
dsconfig get-oauth2-client-prop --client-name "Groovy Sign In Sample" \
  --property client-secret --script-friendly | cut -f 2
```

Next, create an application configuration file.
Copy `src/ratpack/config.example.yaml` to `src/ratpack/config.yaml`
and adjust the values as appropriate.

```
# Set to false ONLY when using a test server.
strictHttpsValidation: false

authorizeEndpoint: https://example.com/oauth/authorize
tokenEndpoint: https://example.com/oauth/token
logoutEndpoint: https://example.com/oauth/logout
jwksEndpoint: https://example.com/jwks
accountManagerUri: https://example.com/samples/my-account
scimEndpoint: https://example.com/scim/v2
idTokenSigningAlgorithm: RS256

clientId: groovy-sign-in-sample
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

To test, load [http://localhost:5050/protected](http://localhost:5050/protected)
in your web browser. This endpoint will detect that you are not authenticated
and redirect you to the configured authentication server. Upon successful
authentication, you will be redirected back to the sample application. The
presence of a logout link will indicate that you are authenticated. If you
return to the `/protected` endpoint, it will detect that you are logged in,
perform a GET on the SCIM `/Me` endpoint, and present the results.

## About this sample application

This sample application is written using the [Groovy](http://groovy-lang.org)
language and the [Ratpack](https://ratpack.io) framework. These were chosen
due to their concision and readability. If you've written Java or JavaScript
before, you should find this application's source code easy to follow.

### Main

The entry point to the application is `src/ratpack/Ratpack.groovy`. This class
binds the application's various modules and services to an object registry that
is available throughout the application via a Context object. The handlers
section of this class acts as a router, defining application endpoints and the
classes or closures that handle requests to those endpoints.

### Configuration

The application configuration is defined by `src/main/groovy/com/example/app/models/AppConfig`.
The class defines default values, which may be overridden by `src/ratpack/config.yaml`.

An AppConfig object is available to all handlers via the Context.

### Services

Services are special classes that can hook into the application lifecycle and
execute code at startup and/or shutdown. This application defines two custom
services.

* **ConfigService**: Inserts dynamically generated values into the application
config at startup. Currently, this is used to generate a private signing key
that the application uses to sign JWTs that it creates.
* **JwksService**: Periodically polls the authentication server's JWKS endpoint
for changes. Keys retrieved from this endpoint are used to verify access tokens
and ID tokens issued by the authentication server.

### Handlers

Incoming requests are dispatched to handlers for processing. Most but not all
handlers in this application are tied to particular request paths.

* **SessionHandler**: Invoked for every request. Checks for a session and creates
one when one doesn't already exist.
* **DefaultProtectedResourceHandler** `/protected/default`: Represents an
application resource that may not be accessed by an unauthenticated user. If
the user is not authenticated, then this handler will redirect to the login
endpoint. If the user is authenticated, then this handler will perform a SCIM
request and display the result.
* **ScopeProtectedResourceHandler** `/protected/scope`: Represents an
application resource that may not be accessed unless the user has authorized a
specific scope. This demonstrates how an application might check granted scopes
subsequent to an authorization.
* **AcrProtectedResourceHandler** `/protected/acr`: Represents an application
resource that may not be accessed unless the user's authentication state
satisfies a particular AMR. This demonstrates how an application may make an
authorization decision based on information about the user's authentication
state contained in the ID token.
* **LoginHandler** `/login`: Creates an OpenID Connect request and redirects to
the authentication server.
* **CallbackHandler** `/callback`: Receives an OpenID Connect redirect response,
validates the response, marks the session as authenticated, and redirects to
the root endpoint.
* **LogoutHandler** `/logout`: Marks the session as unauthenticated and
redirects to the root endpoint.

### Logging out

The application's `/logout` endpoint ends the user's _application session_.
It does not log the user out of the Data Broker. This means that the user can
log out of the sample application, then attempt some action requiring a login,
and the user may be re-authenticated to the application without any prompting
from the Data Broker. Behind the scenes, the application will have sent an
OpenID Connect request to the Data Broker, but since the user is still
authenticated there, it will appear to the user as if a login occurred
instantly. This may or may not be the desired user experience. Bear in mind
that an application has various means at its disposal for forcing
authentication prompts, such as the `prompt` and `max_age` request parameters.

To log out from both the sample application and the Data Broker, you can use
the **SingleSignOutHandler** at `/logout/broker`. This handler, which is not
exposed via the UI, can be used as a shortcut to clearing the authentication
state of the current user.

## Notes

* By default, the application listens on an unsecured HTTP port. Please be
aware that a production web application should always be served using HTTPS.
* The application does not support encrypted ID tokens. This is left as an
exercise for the reader.

## Support and reporting bugs

This sample is not officially supported, but support will be provided
on a best-effort basis through GitHub. Please be aware that this sample is
provided for demonstration purposes and is not intended to be production-ready.

Please report issues using the project's
[issue tracker](https://github.com/UnboundID/broker-groovy-sign-in-sample/issues).

## License

This is licensed under the Apache License 2.0.