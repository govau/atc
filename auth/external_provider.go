package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"golang.org/x/net/context"

	"code.cloudfoundry.org/lager"
	"golang.org/x/oauth2"

	"github.com/concourse/atc"
	"github.com/concourse/atc/auth/provider"
	"github.com/concourse/atc/auth/routes"
	flags "github.com/jessevdk/go-flags"
	"github.com/tedsuo/rata"
)

const externalProviderName = "external"

type ExternalAuthConfig struct {
	DisplayName  string `json:"display_name,omitempty" long:"display-name" description:"Name of external provider"`
	URL          string `json:"url,omitempty" long:"url" description:"Endpoint to initiate login"`
	ClientID     string `json:"client_id,omitempty" long:"client-id" description:"Client ID"`
	ClientSecret string `json:"client_secret,omitempty" long:"client-secret" description:"Client Secret"`
}

func (auth *ExternalAuthConfig) AuthMethod(oauthBaseURL string, teamName string) atc.AuthMethod {
	path, err := routes.OAuthRoutes.CreatePathForRoute(
		routes.OAuthBegin,
		rata.Params{"provider": externalProviderName},
	)
	if err != nil {
		panic("failed to construct oauth begin handler route: " + err.Error())
	}

	path = path + fmt.Sprintf("?team_name=%s", teamName)

	return atc.AuthMethod{
		Type:        atc.AuthTypeOAuth,
		DisplayName: auth.DisplayName,
		AuthURL:     oauthBaseURL + path,
	}
}

func (auth *ExternalAuthConfig) IsConfigured() bool {
	return auth.URL != "" && auth.ClientID != "" && auth.ClientSecret != "" && auth.DisplayName != ""
}

func (auth *ExternalAuthConfig) Validate() error {
	if !auth.IsConfigured() {
		return errors.New("must specify url, client_id, client_secret and display_name")
	}
	return nil
}

func init() {
	provider.Register("external", &externalProviderFactory{})
}

type externalProviderFactory struct{}

func (ep *externalProviderFactory) ProviderConstructor(config provider.AuthConfig, redirectURL string) (provider.Provider, bool) {
	return &externalAuthProvider{
		Config:   config.(*ExternalAuthConfig),
		Callback: redirectURL,
	}, true
}

func (ep *externalProviderFactory) AddAuthGroup(group *flags.Group) provider.AuthConfig {
	flags := &ExternalAuthConfig{}

	eaGroup, err := group.AddGroup("External Authentication", "", flags)
	if err != nil {
		panic(err)
	}

	eaGroup.Namespace = "external-auth"

	return flags
}

func (ep *externalProviderFactory) UnmarshalConfig(message *json.RawMessage) (provider.AuthConfig, error) {
	var rv ExternalAuthConfig
	if message != nil {
		err := json.Unmarshal(*message, &rv)
		if err != nil {
			return nil, err
		}
	}
	return &rv, nil
}

type externalAuthProvider struct {
	Config   *ExternalAuthConfig
	Callback string
}

func (eap *externalAuthProvider) PreTokenClient() (*http.Client, error) {
	return http.DefaultClient, nil
}

func (eap *externalAuthProvider) AuthCodeURL(state string, _ ...oauth2.AuthCodeOption) string {
	return eap.Config.URL + "/v1/login?" + url.Values(map[string][]string{
		"state":     {state},
		"callback":  {eap.Callback},
		"client_id": {eap.Config.ClientID},
	}).Encode()
}

func (eap *externalAuthProvider) Exchange(ctx context.Context, authCode string) (*oauth2.Token, error) {
	csrf, ok := ctx.Value(csrfTokenClaimKey).(string)
	if !ok {
		return nil, errors.New("no csrf in context")
	}
	if csrf == "" {
		return nil, errors.New("no csrf in context")
	}
	resp, err := http.PostForm(eap.Config.URL+"/v1/token", url.Values{
		"csrf":          {csrf},
		"code":          {authCode},
		"client_id":     {eap.Config.ClientID},
		"client_secret": {eap.Config.ClientSecret},
	})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("bad status code returned")
	}
	var t oauth2.Token
	err = json.NewDecoder(resp.Body).Decode(&t)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (eap *externalAuthProvider) Client(ctx context.Context, token *oauth2.Token) *http.Client {
	return http.DefaultClient
}

func (eap *externalAuthProvider) Verify(lager.Logger, *http.Client) (bool, error) {
	return false, nil
}
