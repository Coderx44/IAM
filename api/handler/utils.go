package handler

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/Coderx44/oauth_and_saml/middlewares"
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

func revokeToken(token, tokenType string) error {
	client := &http.Client{}

	data := url.Values{}

	data.Set("token", token)
	data.Set("token_type_hint", tokenType)

	req, err := http.NewRequest("POST", os.Getenv("REVOKE_TOKEN_URL"), strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Authorization", "Basic MG9hYTNuZW0xM0p0NndDejU2OTc6YkM3Z3VsMkltTld2X0ZoTmFSU2RlM0pIbEIydjFnWEFDdFB0R1dyd3ljc1VQRFJLdG5FUFN6aEVKN3A4LU1ZZg==")
	res, err := client.Do(req)
	if err != nil {
		log.Printf("error revoking token: %v", err)
		return err
	}

	if res.StatusCode != http.StatusOK {
		log.Printf("bad request, err: %d", res.StatusCode)
		return errors.New("internal Server Error")
	}

	return nil
}

func getSession(r *http.Request) (*sessions.Session, error) {

	session, err := middlewares.Store.Get(r, middlewares.SessionName)
	if err != nil {
		return session, err
	}

	return session, nil
}
