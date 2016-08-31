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
import groovy.util.logging.Slf4j
import ratpack.handling.Context
import ratpack.session.Session

import static com.example.app.util.ScimClient.me
import static ratpack.handlebars.Template.handlebarsTemplate

/**
 * An example protected resource handler. Displays content if the user is
 * authenticated. Otherwise, redirects to the login handler.
 */
@Slf4j
class DefaultProtectedResourceHandler extends ProtectedResourceHandler {
  @Override
  Set<String> getScopes() {
    return [ "openid", "name", "email" ]
  }

  @Override
  Set<String> getRequiredScopes() {
    return getScopes()
  }

  @Override
  String getDescription() {
    return "This page displays a SCIM resource that is only available if the " +
            "user is logged in to the Data Broker."
  }

  @Override
  void handle(Context ctx) throws Exception {
    String returnUri = ctx.getRequest().getUri()
    AppSession.fromContext(ctx).then { AppSession appSession ->
      if (appSession.getAuthenticated()) {
        String resource =
                me(ctx.get(AppConfig), appSession.getAccessToken()).toString()
        ctx.render(handlebarsTemplate("resource-success", [
                authenticated: appSession.getAuthenticated(),
                description: getDescription(),
                resource: resource,
                returnUri: returnUri
        ], "text/html"))
      } else {
        log.info("Unauthenticated user attempting to access a protected resource")
        log.info("Sending login request")

        appSession.setRequiredScopes(getRequiredScopes())
        appSession.setRequiredAcrs(null)
        Session session = ctx.get(Session)
        session.set("s", appSession).onError {
          throw new SessionException("Failed to update session")
        }.then {
          ctx.redirect loginPath(returnUri, null)
        }
      }
    }
  }
}
