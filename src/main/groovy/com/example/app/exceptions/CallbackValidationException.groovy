package com.example.app.exceptions

/**
 * Represents a validation error during OpenID Connect response processing.
 */
class CallbackValidationException extends Exception {
  CallbackValidationException(String message) {
    super(message)
  }
}
