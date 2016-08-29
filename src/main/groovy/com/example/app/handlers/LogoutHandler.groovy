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

import com.example.app.models.AppSession
import groovy.util.logging.Slf4j
import ratpack.handling.Context
import ratpack.handling.Handler
import ratpack.session.Session

/**
 * TODO: Description goes here.
 */
@Slf4j
class LogoutHandler implements Handler {
  @Override
  void handle(Context ctx) throws Exception {
    AppSession.fromContext(ctx).then { AppSession appSession ->
      log.info("Logging out")
      appSession.setAuthenticated(false)
      appSession.setAccessToken(null)
      appSession.setIdToken(null)
      Session session = ctx.get(Session)
      session.set("s", appSession).onError {
        throw new RuntimeException("Failed to update session")
      }.then {
        ctx.redirect "/"
      }
    }
  }
}
