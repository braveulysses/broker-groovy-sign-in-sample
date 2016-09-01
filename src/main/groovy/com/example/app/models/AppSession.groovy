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

import com.example.app.exceptions.SessionException
import ratpack.exec.Promise
import ratpack.func.Block
import ratpack.handling.Context
import ratpack.session.Session

import java.security.SecureRandom

/**
 * The application session model.
 */
class AppSession implements Serializable {
  public final static String SESSION_KEY = "s"

  // A stored session state JWT that will be attached to an authentication
  // request and then returned in an authentication response.
  String state
  // A unique session identifier that the authentication server is expected to
  // include in an ID token.
  String nonce
  // A session-specific secret that is used to sign the state JWT.
  String sessionSecret
  // Whether or not the user is considered authenticated.
  Boolean authenticated
  // The access token received from the authentication server.
  String accessToken
  // The ID token received from the authentication server.
  String idToken
  // Required scopes. A resource handler may populate this so that it can be
  // consumed by the login handler.
  Set<String> requiredScopes
  // Acceptable ACRs. A resource handler may populate this so that it can be
  // consumed by the login handler.
  Set<String> acceptableAcrs

  public AppSession() {
    SecureRandom random = new SecureRandom()
    this.nonce = generateUniqueValue(random)
    this.sessionSecret = generateUniqueValue(random)
    this.authenticated = false
  }

  /**
   * Generates a new nonce value. This should be called before making a new
   * authentication request to ensure that each nonce is unique.
   */
  public void updateNonce() {
    SecureRandom random = new SecureRandom()
    nonce = generateUniqueValue(random)
  }

  /**
   * Saves this AppSession instance.
   *
   * @param ctx
   *          The request context.
   * @param block
   *          A closure to be executed after the session is successfully updated.
   */
  public void save(Context ctx, Block block) {
    Session session = ctx.get(Session)
    session.set(SESSION_KEY, this).onError {
      throw new SessionException("Failed to update session")
    }.then {
      block.execute()
    }
  }

  /**
   * Creates an AppSession instance from the request context.
   *
   * @param ctx
   *          The request context.
   * @return An AppSession instance.
   */
  public static Promise<AppSession> fromContext(Context ctx) {
    AppSession appSession = new AppSession();
    return Promise.async { downstream ->
      ctx.get(Session).get(SESSION_KEY).then { optional ->
        appSession = optional.get() as AppSession
        downstream.success(appSession)
      }
    }
  }

  private static String generateUniqueValue(Random random) {
    return new BigInteger(130, random).toString(32)
  }
}
