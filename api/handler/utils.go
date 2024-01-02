package handler

import (
	"net/http"

	"github.com/gorilla/sessions"
	jwtverifier "github.com/okta/okta-jwt-verifier-golang"
)

func decodeToken(r *http.Request) (userInfo UserInfo, err error) {

	session := r.Context().Value("okta-session").(*sessions.Session)
	idToken := session.Values["id_token"].(string)
	toValidate := map[string]string{}
	toValidate["aud"] = "0oaa3nem13Jt6wCz5697"

	jwtVerifierSetup := jwtverifier.JwtVerifier{
		Issuer:           "https://trial-8230984.okta.com/oauth2/default",
		ClaimsToValidate: toValidate,
	}

	verifier := jwtVerifierSetup.New()

	token, err := verifier.VerifyIdToken(idToken)
	if err != nil {
		return userInfo, err
	}

	userInfo = UserInfo{
		Name:  token.Claims["name"].(string),
		Email: token.Claims["email"].(string),
		Type:  "oauth",
	}

	return userInfo, nil

}
