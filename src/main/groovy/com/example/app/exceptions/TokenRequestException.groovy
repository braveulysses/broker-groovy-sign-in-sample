package com.example.app.exceptions

/**
 * Represents an error in the token request process.
 */
class TokenRequestException extends Exception {
  TokenRequestException(String message) {
    super(message)
  }

  TokenRequestException(String message, Throwable throwable) {
    super(message, throwable)
  }
}
