package registry

import (
	"context"
	"errors"
	"net/http"
)

// Check authenticates against https://<host>/v2/ with the credentials,
// through the same guarded client as pulls (the registry test endpoint).
// errKind is "" when ok, else ReasonUnauthorized, ReasonBlocked or
// ReasonUnreachable. A registry that answers /v2/ without asking for
// credentials is ok: there is nothing to refuse them.
func (c *Client) Check(ctx context.Context, host, username, password string) (ok bool, errKind string) {
	if err := checkHost(host); err != nil {
		return false, ReasonUnreachable
	}
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	s := c.session(host, &Credentials{Username: username, Password: password}, "")
	defer s.close()
	resp, err := s.get(ctx, "/v2/", nil)
	if err == nil {
		if resp.StatusCode == http.StatusOK {
			drain(resp.Body)
			return true, ""
		}
		err = s.statusError(resp, "/v2/")
	}
	var e *Error
	if errors.As(err, &e) {
		switch r := e.Reason(); r {
		case ReasonUnauthorized, ReasonBlocked:
			return false, r
		}
	}
	return false, ReasonUnreachable
}
