package com.example.app.handlers

import com.example.app.models.AppSession
import ratpack.handling.Context
import ratpack.handling.Handler

import static ratpack.handlebars.Template.handlebarsTemplate

/**
 * Handler for the root application path. The user is not required to be
 * authenticated to see content from this path.
 */
class RootHandler implements Handler {
  @Override
  void handle(Context ctx) throws Exception {
    AppSession.fromContext(ctx).then { AppSession appSession ->
      ctx.render(handlebarsTemplate("index", [
              authenticated: appSession.getAuthenticated(),
              returnUri: ctx.getRequest().getUri()
      ], "text/html"))
    }
  }
}
