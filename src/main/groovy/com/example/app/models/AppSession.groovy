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
package com.example.app.models

import ratpack.exec.Promise
import ratpack.handling.Context
import ratpack.session.Session

import java.security.SecureRandom

/**
 * The application session model.
 */
class AppSession implements Serializable {
  String state
  String nonce
  String sessionSecret
  Boolean authenticated
  String accessToken
  String idToken

  public AppSession() {
    SecureRandom random = new SecureRandom()
    this.nonce = generateUniqueValue(random)
    this.sessionSecret = generateUniqueValue(random)
    this.authenticated = false
  }

  public void updateNonce() {
    SecureRandom random = new SecureRandom()
    nonce = generateUniqueValue(random)
  }

  public static Promise<AppSession> fromContext(Context ctx) {
    AppSession appSession = new AppSession();
    return Promise.async { downstream ->
      ctx.get(Session).get("s").then { optional ->
        appSession = optional.get() as AppSession
        downstream.success(appSession)
      }
    }
  }

  private static String generateUniqueValue(Random random) {
    return new BigInteger(130, random).toString(32)
  }
}
