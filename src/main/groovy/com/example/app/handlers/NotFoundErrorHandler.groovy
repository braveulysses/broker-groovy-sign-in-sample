package com.example.app.handlers

import com.example.app.models.AppSession
import io.netty.handler.codec.http.HttpResponseStatus
import ratpack.error.ClientErrorHandler
import ratpack.handling.Context

import static ratpack.handlebars.Template.handlebarsTemplate

/**
 * An error handler for 404 Page Not Found errors. This handler could actually
 * be used to handle any kind of client error, but only 404s are expected in
 * practice.
 */
class NotFoundErrorHandler implements ClientErrorHandler {
  @Override
  void error(Context ctx, int statusCode) throws Exception {
    AppSession.fromContext(ctx).then { AppSession appSession ->
      ctx.response.status(HttpResponseStatus.NOT_FOUND.code())
      ctx.render(handlebarsTemplate("exception-generic", [
              authenticated: appSession.getAuthenticated(),
              returnUri: ctx.getRequest().getUri(),
              message: "Page not found"
      ], "text/html"))
    }
  }
}
