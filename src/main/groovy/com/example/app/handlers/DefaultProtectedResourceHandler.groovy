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
package com.example.app.handlers

import com.example.app.exceptions.SessionException
import com.example.app.models.AppConfig
import com.example.app.models.AppSession
import com.example.app.util.ScimClient
import com.unboundid.scim2.client.ScimService
import com.unboundid.scim2.common.GenericScimResource
import groovy.util.logging.Slf4j
import ratpack.handling.Context
import ratpack.handling.Handler
import ratpack.http.HttpUrlBuilder
import ratpack.session.Session

import java.util.stream.Collectors

import static ratpack.handlebars.Template.handlebarsTemplate

/**
 * An example protected resource handler. Displays content if the user is
 * authenticated. Otherwise, redirects to the login handler.
 */
@Slf4j
class DefaultProtectedResourceHandler implements Handler {
  // The scopes to request.
  Set<String> scopes = [ "openid", "name", "email" ]

  @Override
  void handle(Context ctx) throws Exception {
    String returnUri = ctx.getRequest().getUri()
    AppSession.fromContext(ctx).then { AppSession appSession ->
      if (appSession.getAuthenticated()) {
        String resource = me(ctx.get(AppConfig), appSession.getAccessToken()).toString()
        ctx.render(handlebarsTemplate("resource", [
                authenticated: appSession.getAuthenticated(),
                resource: resource,
                returnUri: returnUri
        ], "text/html"))
      } else {
        log.info("Unauthenticated user attempting to access a protected resource")
        log.info("Sending login request")

        appSession.setRequiredScopes(scopes)
        Session session = ctx.get(Session)
        session.set("s", appSession).onError {
          throw new SessionException("Failed to update session")
        }.then {
          String requestedScopes = scopes.stream().collect(Collectors.joining(' '))
          String requiredScopes = requestedScopes
          ctx.redirect "/login?return_uri=${returnUri}&scope=${requestedScopes}" +
                               "&required_scope=${requiredScopes}"
        }
      }
    }
  }

  private static GenericScimResource me(AppConfig config, String bearerToken) {
    URI meEndpoint = HttpUrlBuilder.base(new URI(config.getScimEndpoint()))
            .path("Me")
            .build()
    ScimService scimService = ScimClient.createInstance(config, bearerToken)
    return scimService.retrieve(meEndpoint, GenericScimResource)
  }
}
