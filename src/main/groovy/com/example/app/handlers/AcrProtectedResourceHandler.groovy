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
import com.nimbusds.jwt.SignedJWT
import groovy.util.logging.Slf4j
import ratpack.handling.Context
import ratpack.handling.Handler
import ratpack.session.Session

import java.util.stream.Collectors

import static com.example.app.util.ScimClient.me
import static ratpack.handlebars.Template.handlebarsTemplate

/**
 * An example protected resource handler. Displays content if the user is
 * authenticated and has authenticated with a certain ACR. If the user is
 * authenticated but has not satisfied this ACR, then the user is given a
 * chance to re-authenticate and/or enable a second factor. Otherwise, it
 * redirects to the login handler.
 */
@Slf4j
class AcrProtectedResourceHandler implements Handler {
  // The scopes to request.
  Set<String> scopes = [ "openid", "name", "email", "phone", "birthday" ]
  // The scopes that must be authorized.
  Set<String> requiredScopes = [ "openid" ] as Set
  // A description of this resource handler.
  String description = "This page displays a SCIM resource that is " +
          "only available if the user is logged in to the Data " +
          "Broker and has been authenticated with the <em>MFA</em> ACR."
  // Step-up instructions for the user.
  String instructions = "To view this page's protected resource, you'll need " +
          "to re-authenticate using multi-factor authentication. You may first " +
          "need to edit your account to enable a second factor."

  @Override
  void handle(Context ctx) throws Exception {
    AppConfig config = ctx.get(AppConfig)
    String returnUri = ctx.getRequest().getUri()
    AppSession.fromContext(ctx).then { AppSession appSession ->
      if (appSession.getAuthenticated()) {
        // Check the ID token for the required ACR.
        JWT idToken = SignedJWT.parse(appSession.getIdToken())
        log.info("Checking saved ID token for 'MFA' ACR")
        log.info("ID token claims: {}", idToken.getJWTClaimsSet().toString())
        String acr = idToken.getJWTClaimsSet().getStringClaim("acr")
        if (acr == "MFA") {
          // User's authentication satisfied the 'MFA' ACR; display the resource.
          log.info("User logged in with 'MFA' ACR")
          String resource = me(config, appSession.getAccessToken()).toString()
          ctx.render(handlebarsTemplate("resource-success", [
                  authenticated: appSession.getAuthenticated(),
                  description: description,
                  resource: resource,
                  returnUri: returnUri
          ], "text/html"))
        } else {
          // User's authentication did not satisfy the 'MFA' ACR; the user will
          // need to authenticate again. The user might also need to edit his
          // or her account first to enable a second factor.
          log.info("User will need to re-authenticate with the 'MFA' ACR")
          appSession.setRequiredScopes(requiredScopes)
          appSession.setRequiredAcrs(null)
          Session session = ctx.get(Session)
          session.set("s", appSession).onError {
            throw new SessionException("Failed to update session")
          }.then {
            ctx.render(handlebarsTemplate("resource-step-up", [
                    authenticated: appSession.getAuthenticated(),
                    description: description,
                    instructions: instructions,
                    returnUri: returnUri,
                    loginPath: loginPath(returnUri, "consent"),
                    accountManagerUri: config.getAccountManagerUri()
            ], "text/html"))
          }
        }
      } else {
        log.info("Unauthenticated user attempting to access a protected resource")
        log.info("Sending login request")
        appSession.setRequiredScopes(scopes)
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

  private String loginPath(String returnUri, String prompt) {
    String requestedScopes = scopes.stream().collect(Collectors.joining(' '))
    String loginPath = "/login?return_uri=${returnUri}&scope=${requestedScopes}" +
            "&required_scope=${requiredScopes}"
    if (prompt) {
      loginPath = loginPath + "&prompt=" + prompt
    }
    return loginPath
  }
}
