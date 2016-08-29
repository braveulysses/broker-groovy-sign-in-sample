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

import static groovy.json.JsonOutput.toJson

/**
 * The application's in-memory session handler. Creates a session if one
 * doesn't already exist.
 */
@Slf4j
class SessionHandler implements Handler {
  @Override
  void handle(Context ctx) throws Exception {
    Session session = ctx.get(Session)
    session.get("s").flatMap { optional ->
      AppSession appSession = optional.orElse(new AppSession()) as AppSession
      log.info("Authentication state: ${appSession.getAuthenticated()}")
      session.set("s", appSession).promise()
    }.then {
      ctx.next()
    }
  }
}
