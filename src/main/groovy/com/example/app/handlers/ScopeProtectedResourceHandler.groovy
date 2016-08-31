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
import com.nimbusds.jwt.JWT
import groovy.util.logging.Slf4j
import ratpack.handling.Context
import ratpack.session.Session

import static com.example.app.util.ScimClient.me
import static com.example.app.util.TokenUtil.verifySignedAccessToken
import static ratpack.handlebars.Template.handlebarsTemplate

/**
 * An example protected resource handler. Displays content if the user is
 * authenticated and has authorized a particular scope. If the user is
 * authenticated but has not authorized this scope, then the user is given a
 * chance to reauthorize. Otherwise, it redirects to the login handler.
 */
@Slf4j
class ScopeProtectedResourceHandler extends ProtectedResourceHandler {
  @Override
  String getDescription() {
    return "This page displays a SCIM resource that is only available if the " +
            "user is logged in to the Data Broker and has been authorized for " +
            "the <em>phone</em> scope."
  }

  @Override
  String getStepUpInstructions() {
    return "To view this page's protected resource, you'll need to authorize " +
            "again and accept all scopes."
  }

  @Override
  Set<String> getScopes() {
    return [ "openid", "name", "email", "phone" ]
  }

  @Override
  Set<String> getRequiredScopes() {
    return [ "openid" ] as Set
  }

  @Override
  List<String> getACRs() {
    return null
  }

  @Override
  Set<String> getAcceptableACRs() {
    return null
  }

  @Override
  void handle(Context ctx) throws Exception {
    AppConfig config = ctx.get(AppConfig)
    String returnUri = ctx.getRequest().getUri()
    AppSession.fromContext(ctx).then { AppSession appSession ->
      if (appSession.getAuthenticated()) {
        // Verify the access token's signature and check it for the "phone" scope.
        JWT accessToken =
                verifySignedAccessToken(config, appSession.getAccessToken())
        Set<String> grantedScopes = accessToken.getJWTClaimsSet()
                .getStringClaim("scope").split(' ') as Set
        if (grantedScopes.contains("phone")) {
          // User was granted the phone scope; display the resource.
          String resource = me(config, appSession.getAccessToken()).toString()
          ctx.render(handlebarsTemplate("resource-success", [
                  authenticated: appSession.getAuthenticated(),
                  description: getDescription(),
                  resource: resource,
                  returnUri: returnUri
          ], "text/html"))
        } else {
          // User was not granted the phone scope; the user will need to
          // authorize again.
          log.info("User will need to authorize the 'phone' scope")
          appSession.setRequiredScopes(getRequiredScopes())
          appSession.setAcceptableAcrs(null)
          Session session = ctx.get(Session)
          session.set("s", appSession).onError {
            throw new SessionException("Failed to update session")
          }.then {
            ctx.render(handlebarsTemplate("resource-step-up", [
                    authenticated: appSession.getAuthenticated(),
                    description: getDescription(),
                    instructions: getStepUpInstructions(),
                    returnUri: returnUri,
                    loginPath: loginPath(returnUri, "consent")
            ], "text/html"))
          }
        }
      } else {
        log.info("Unauthenticated user attempting to access a protected resource")
        log.info("Sending login request")
        appSession.setRequiredScopes(getRequiredScopes())
        appSession.setAcceptableAcrs(null)
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
