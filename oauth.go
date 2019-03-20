package robinhood

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/oauth2"
)

// DefaultClientID is used by the website.
const DefaultClientID = "c82SH0WZOsabOXGP2sxqcj34FxkvfnWRZBKlBjFS"

// OAuth implements oauth2 using the robinhood implementation
type OAuth struct {
	Endpoint, ClientID, Username, Password, MFA string

	PasswordProvider CredentialGetter
	MFAProvider      CredentialGetter
}

type CredentialGetter interface {
	GetCredential() (string, error)
}

type terminalCredentialGetter struct {
	prompt string
}

func NewTerminalCredentialGetter(prompt string) CredentialGetter {
	return &terminalCredentialGetter{
		prompt: prompt,
	}
}

func (p *terminalCredentialGetter) GetCredential() (string, error) {
	if !terminal.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("robinhood/oauth: requesting terminal credentials outside of a tty")
	}
	fmt.Print(p.prompt)
	cred, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}
	fmt.Print("\n")
	return string(cred), nil
}

// ErrMFARequired indicates the MFA was required but not provided.
var ErrMFARequired = fmt.Errorf("Two Factor Auth code required and not supplied")

// Token implements TokenSource
func (p *OAuth) Token() (*oauth2.Token, error) {
	if p.PasswordProvider != nil {
		password, err := p.PasswordProvider.GetCredential()
		if err != nil {
			return nil, errors.Wrap(err, "could not get password")
		}
		p.Password = password
	}
	if p.MFAProvider != nil {
		mfa, err := p.MFAProvider.GetCredential()
		if err != nil {
			return nil, errors.Wrap(err, "could not get mfa")
		}
		p.MFA = mfa
	}

	ep := p.Endpoint
	if ep == "" {
		ep = EPLogin
	}

	cliID := p.ClientID
	if cliID == "" {
		cliID = DefaultClientID
	}

	u, _ := url.Parse(EPLogin)
	q := u.Query()
	q.Add("expires_in", fmt.Sprint(24*time.Hour/time.Second))
	q.Add("client_id", cliID)
	q.Add("grant_type", "password")
	q.Add("scope", "internal")
	u.RawQuery = q.Encode()

	v := url.Values{
		"username": []string{p.Username},
		"password": []string{p.Password},
	}
	if p.MFA != "" {
		v.Add("mfa_code", p.MFA)
	}

	req, err := http.NewRequest(
		"POST",
		u.String(),
		strings.NewReader(v.Encode()),
	)
	if err != nil {
		return nil, errors.Wrap(err, "could not create request")
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "could not post login")
	}
	defer res.Body.Close()

	var o struct {
		oauth2.Token
		ExpiresIn   int    `json:"expires_in"`
		MFARequired bool   `json:"mfa_required"`
		MFAType     string `json:"mfa_type"`
	}

	err = json.NewDecoder(res.Body).Decode(&o)
	if err != nil {
		return nil, errors.Wrap(err, "could not decode token")
	}

	if o.MFARequired {
		return nil, ErrMFARequired
	}

	o.Token.Expiry = time.Now().Add(time.Duration(o.ExpiresIn) * time.Second)

	return &o.Token, nil
}
