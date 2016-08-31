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
package com.example.app.exceptions

/**
 * Represents an OAuth 2/OpenID Connect error response returned by the
 * authentication server.
 */
class CallbackErrorException extends Exception {
  String error
  String errorDescription

  CallbackErrorException(String message, String error, String errorDescription) {
    super(message)
    this.error = error
    this.errorDescription = errorDescription
  }
}
