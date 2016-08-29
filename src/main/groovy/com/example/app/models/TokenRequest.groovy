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

/**
 * An OAuth 2 token request.
 */
class TokenRequest {
  String grantType = "authorization_code"
  String code
  URI redirectURI

  /**
   * Returns this token request as a form-urlencoded string.
   *
   * @return This token request as a form-urlencoded string.
   */
  public String formUrlEncoded() {
    return "grant_type=${grantType}&code=${code}&redirect_uri=${redirectURI}"
  }
}
