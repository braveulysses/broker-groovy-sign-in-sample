/*
 * Copyright 2016 UnboundID Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


import com.example.app.handlers.NotFoundErrorHandler
import com.example.app.handlers.RootHandler
import com.example.app.models.AppConfig
import com.example.app.handlers.CallbackHandler
import com.example.app.handlers.DefaultServerErrorHandler
import com.example.app.handlers.LoginHandler
import com.example.app.handlers.LogoutHandler
import com.example.app.handlers.DefaultProtectedResourceHandler
import com.example.app.handlers.SessionHandler
import com.example.app.models.AppSession
import com.example.app.services.JwksService
import com.example.app.services.ConfigService
import com.nimbusds.jose.jwk.JWKSet
import ratpack.error.ClientErrorHandler
import ratpack.error.ServerErrorHandler
import ratpack.handlebars.HandlebarsModule
import ratpack.handling.Context
import ratpack.handling.RequestLogger
import ratpack.http.MediaType
import ratpack.session.SessionModule

import static ratpack.groovy.Groovy.ratpack
import static groovy.json.JsonOutput.toJson

/**
 * This is the application's entry point. Bindings for modules, services, and
 * request handlers are defined here.
 */
ratpack {
  serverConfig {
    yaml "config.yaml"
    require("", AppConfig)
  }

  bindings {
    module SessionModule
    module(HandlebarsModule) { HandlebarsModule.Config config ->
      config.templatesPath "templates"
    }
    bind ConfigService
    bind JwksService
    add RequestLogger.ncsa()
    bindInstance ServerErrorHandler, new DefaultServerErrorHandler()
    bindInstance ClientErrorHandler, new NotFoundErrorHandler()
    add new SessionHandler()
    add new RootHandler()
    add new CallbackHandler()
    add new LoginHandler()
    add new LogoutHandler()
    add new DefaultProtectedResourceHandler()
  }

  handlers {
    // Log all requests.
    all(RequestLogger)

    // Always check for a session.
    all(SessionHandler)

    // Root path handler ('/').
    get(RootHandler)

    // Login handler. Forms an OpenID Connect request and redirects to the
    // authentication server.
    get("login", LoginHandler)

    // OpenID Connect callback handler. Receives an authorization code and
    // exchanges it for an access token. Authenticates the current session.
    get("callback", CallbackHandler)

    // Logout handler. De-authenticates the current session.
    get("logout", LogoutHandler)

    // Example protected resource handler. Requires the user to have an
    // authenticated session.
    get("protected", DefaultProtectedResourceHandler)
    get("protected/default", DefaultProtectedResourceHandler)

    // Diagnostic endpoint for the application config.
    get("config") { AppConfig config ->
      response.contentType(MediaType.APPLICATION_JSON).send(toJson(config))
    }

    // Diagnostic endpoint for the application session.
    get("session") { Context ctx ->
      AppSession.fromContext(ctx).then { AppSession appSession ->
        response.contentType(MediaType.APPLICATION_JSON).send(toJson(appSession))
      }
    }

    // Diagnostic endpoint for confirming the JWKS fetched from the
    // authentication server.
    get("jwks") { Context ctx ->
      JWKSet jwkSet = ctx.get(AppConfig).getJwks()
      response.contentType(MediaType.APPLICATION_JSON).send(jwkSet.toString())
    }

    // Static files.
    files {
      dir("static").indexFiles("index.html")
    }
  }
}
