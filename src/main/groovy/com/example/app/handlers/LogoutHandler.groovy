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

import com.example.app.exceptions.TokenRevocationException
import com.example.app.models.AppConfig
import com.example.app.models.AppSession
import com.example.app.models.TokenRevocationRequest
import com.example.app.util.HttpsUtil
import groovy.util.logging.Slf4j
import ratpack.handling.Context
import ratpack.handling.Handler
import ratpack.http.MediaType
import ratpack.http.client.HttpClient

/**
 * Logs the user out of the application by flipping the 'authenticated' flag on
 * the session, nulling out the access and ID token stored in the session, and
 * revoking the access token. This does not log the user out of the
 * authentication server.
 */
@Slf4j
class LogoutHandler implements Handler {
  @Override
  void handle(Context ctx) throws Exception {
    AppSession.fromContext(ctx).then { AppSession appSession ->
      log.info("Logging out of application")
      revokeAccessToken(ctx, appSession.getAccessToken())
      appSession.setAuthenticated(false)
      appSession.setAccessToken(null)
      appSession.setIdToken(null)
      appSession.save(ctx) {
        ctx.redirect "/"
      }
    }
  }

  private static void revokeAccessToken(Context ctx, String accessToken) {
    TokenRevocationRequest revocationRequest =
            new TokenRevocationRequest(accessToken)
    AppConfig config = ctx.get(AppConfig)
    HttpClient httpClient = ctx.get(HttpClient)
    httpClient.post(config.getRevokeEndpoint()) { requestSpec ->
      if (!config.isStrictHttpsValidation()) {
        requestSpec.sslContext(HttpsUtil.createInsecureSSLContext())
      }
      requestSpec.headers.add("Content-Type", MediaType.APPLICATION_FORM)
      requestSpec.body { body ->
        body.type(MediaType.APPLICATION_FORM).text(revocationRequest.formUrlEncoded())
      }
    }.onError { throwable ->
      throw new TokenRevocationException("Error while revoking token", throwable)
    }.then {
      log.info("Token revoked")
    }
  }
}
