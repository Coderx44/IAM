package middlewares

import (
	"context"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

var Store = sessions.NewCookieStore([]byte("q1w2e3r4t5"))
var SessionName = "okta-session"

// SessionsMiddleware ...
func SessionsMiddleware() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, err := Store.Get(r, SessionName)

			if err != nil || session.Values["access_token"] == nil || session.Values["access_token"] == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			r = r.WithContext(context.WithValue(r.Context(), SessionName, session))
			next.ServeHTTP(w, r)
		})
	}
}
