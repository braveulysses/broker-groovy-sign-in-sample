package com.example.app.exceptions

/**
 * Represents an error that occurs while reading or updating the application's
 * session state.
 */
class SessionException extends Exception {
  SessionException(String message) {
    super(message)
  }
}
