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
