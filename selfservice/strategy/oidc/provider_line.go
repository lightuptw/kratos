package oidc

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/oauth2"

	"github.com/ory/herodot"
)

type ProviderLine struct {
	*ProviderGenericOIDC
}

func NewProviderLine(
	config *Configuration,
	reg Dependencies,
) Provider {
	return &ProviderLine{
		ProviderGenericOIDC: &ProviderGenericOIDC{
			config: config,
			reg:    reg,
		},
	}
}

type Token struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	Expiry       int    `json:"expires_in"`
	IdToken      string `json:"id_token"`
}


var _ TokenExchanger = (*ProviderLine)(nil)

func (p *ProviderLine) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", p.config.Redir(p.reg.Config().OIDCRedirectURIBase(ctx)))
	data.Set("client_id", p.config.ClientID)
	data.Set("client_secret", p.config.ClientSecret)
	data.Set("id_token_key_type", "JWK")

	resp, err := http.Post("https://api.line.me/oauth2/v2.1/token", "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))

	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	bodyString := string(body)

	token := Token{}
	json.Unmarshal([]byte(bodyString), &token)

	var ot = oauth2.Token{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		RefreshToken: token.RefreshToken,
		Expiry:       time.Unix(int64(token.Expiry), 0),
	}
	var new_ot = ot.WithExtra(map[string]interface{}{"id_token": token.IdToken})
	return new_ot, nil
}

var _ IDTokenVerifier = new(ProviderLine)

func (p *ProviderLine) Verify(ctx context.Context, rawIDToken string) (*Claims, error) {
	data := url.Values{}
	data.Set("id_token", rawIDToken)
	data.Set("client_id", p.config.ClientID)

	resp, err := http.Post(
		"https://api.line.me/oauth2/v2.1/verify", 
		"application/x-www-form-urlencoded", 
		strings.NewReader(data.Encode()),
	)

	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	bodyString := string(body)

	claims := &Claims{}
	json.Unmarshal([]byte(bodyString), &claims)

	return claims, nil
}

var _ NonceValidationSkipper = new(ProviderLine)

func (a *ProviderLine) CanSkipNonce(c *Claims) bool {
	// Not all SDKs support nonce validation, so we skip it if no nonce is present in the claims of the ID Token.
	return c.Nonce == ""
}

func (g *ProviderLine) AuthCodeURLOptions(r ider) []oauth2.AuthCodeOption {
	var options []oauth2.AuthCodeOption

	// if isForced(r) {
	// 	options = append(options, oauth2.SetAuthURLParam("prompt", "login"))
	// }
	if len(g.config.RequestedClaims) != 0 {
		options = append(options, oauth2.SetAuthURLParam("claims", string(g.config.RequestedClaims)))
	}

	return options
}

