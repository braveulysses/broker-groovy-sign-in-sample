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

import ratpack.handling.Handler

import java.util.stream.Collectors

/**
 * Base class for protected resource handlers that require an OpenID Connect
 * authentication to take place before divulging content.
 */
abstract class ProtectedResourceHandler implements Handler {
  /**
   * Returns a description of this resource handler that may be used in the UI.
   *
   * @return A description of this resource handler.
   */
  public abstract String getDescription()

  /**
   * Returns instructions for performing a step-up authentication or
   * authorization, which may be passed to the UI. The default implementation
   * returns {@code null}, since a resource handler may not need step-up.
   *
   * @return Step-up instructions for the user.
   */
  public String getStepUpInstructions() {
    return null
  }

  /**
   * Returns the set of scopes that the resource handler will request when
   * making an OpenID Connect request.
   *
   * @return The scopes to use in an authentication request.
   */
  public abstract Set<String> getScopes()

  /**
   * Returns the set of scopes that the resource handler requires to be
   * authorized. Any scopes in this set will be automatically checked by the
   * callback handler when an authentication response is received; if any are
   * missing, then the request will be considered a failure. Any scopes that
   * the resource handler prefers to check itself should be omitted from this
   * set.
   *
   * @return The set of scopes required by this handler.
   */
  public abstract Set<String> getRequiredScopes()

  /**
   * Returns a request path that may be used to initiate an authentication
   * request from the login endpoint.
   *
   * @param returnUri
   *          The URI to redirect to after a successful authentication response
   *          is received. Usually the URI of this response handler.
   * @param prompt
   *          An OpenID Connect prompt value, such as "consent" or
   *          "login consent". May be {@code null}.
   * @return A login endpoint request path.
   */
  public String loginPath(String returnUri, String prompt) {
    // TODO: Account for empty requestedScopes or requiredScopes
    String requestedScopes = getScopes().stream().collect(Collectors.joining(' '))
    String requiredScopes = getRequiredScopes().stream().collect(Collectors.joining(' '))
    String loginPath = "/login?return_uri=${returnUri}&scope=${requestedScopes}" +
            "&required_scope=${requiredScopes}"
    if (prompt) {
      loginPath = loginPath + "&prompt=" + prompt
    }
    return loginPath
  }
}