// Code generated by go-swagger; DO NOT EDIT.

package admin

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new admin API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for admin API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientService is the interface for Client methods
type ClientService interface {
	CreateIdentity(params *CreateIdentityParams) (*CreateIdentityCreated, error)

	CreateRecoveryLink(params *CreateRecoveryLinkParams) (*CreateRecoveryLinkOK, error)

	DeleteIdentity(params *DeleteIdentityParams) (*DeleteIdentityNoContent, error)

	GetIdentity(params *GetIdentityParams) (*GetIdentityOK, error)

	ListIdentities(params *ListIdentitiesParams) (*ListIdentitiesOK, error)

	Prometheus(params *PrometheusParams) (*PrometheusOK, error)

	UpdateIdentity(params *UpdateIdentityParams) (*UpdateIdentityOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
  CreateIdentity creates an identity

  This endpoint creates an identity. It is NOT possible to set an identity's credentials (password, ...)
using this method! A way to achieve that will be introduced in the future.

Learn how identities work in [ORY Kratos' User And Identity Model Documentation](https://www.ory.sh/docs/next/kratos/concepts/identity-user-model).
*/
func (a *Client) CreateIdentity(params *CreateIdentityParams) (*CreateIdentityCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateIdentityParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "createIdentity",
		Method:             "POST",
		PathPattern:        "/identities",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http", "https"},
		Params:             params,
		Reader:             &CreateIdentityReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*CreateIdentityCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for createIdentity: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  CreateRecoveryLink creates a recovery link

  This endpoint creates a recovery link which should be given to the user in order for them to recover
(or activate) their account.
*/
func (a *Client) CreateRecoveryLink(params *CreateRecoveryLinkParams) (*CreateRecoveryLinkOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateRecoveryLinkParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "createRecoveryLink",
		Method:             "POST",
		PathPattern:        "/recovery/link",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http", "https"},
		Params:             params,
		Reader:             &CreateRecoveryLinkReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*CreateRecoveryLinkOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for createRecoveryLink: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  DeleteIdentity deletes an identity

  Calling this endpoint irrecoverably and permanently deletes the identity given its ID. This action can not be undone.
This endpoint returns 204 when the identity was deleted or when the identity was not found, in which case it is
assumed that is has been deleted already.

Learn how identities work in [ORY Kratos' User And Identity Model Documentation](https://www.ory.sh/docs/next/kratos/concepts/identity-user-model).
*/
func (a *Client) DeleteIdentity(params *DeleteIdentityParams) (*DeleteIdentityNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteIdentityParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "deleteIdentity",
		Method:             "DELETE",
		PathPattern:        "/identities/{id}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json", "application/x-www-form-urlencoded"},
		Schemes:            []string{"http", "https"},
		Params:             params,
		Reader:             &DeleteIdentityReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*DeleteIdentityNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deleteIdentity: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetIdentity gets an identity

  Learn how identities work in [ORY Kratos' User And Identity Model Documentation](https://www.ory.sh/docs/next/kratos/concepts/identity-user-model).
*/
func (a *Client) GetIdentity(params *GetIdentityParams) (*GetIdentityOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetIdentityParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "getIdentity",
		Method:             "GET",
		PathPattern:        "/identities/{id}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http", "https"},
		Params:             params,
		Reader:             &GetIdentityReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetIdentityOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getIdentity: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  ListIdentities lists identities

  Lists all identities. Does not support search at the moment.

Learn how identities work in [ORY Kratos' User And Identity Model Documentation](https://www.ory.sh/docs/next/kratos/concepts/identity-user-model).
*/
func (a *Client) ListIdentities(params *ListIdentitiesParams) (*ListIdentitiesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListIdentitiesParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "listIdentities",
		Method:             "GET",
		PathPattern:        "/identities",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json", "application/x-www-form-urlencoded"},
		Schemes:            []string{"http", "https"},
		Params:             params,
		Reader:             &ListIdentitiesReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*ListIdentitiesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listIdentities: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  Prometheus gets snapshot metrics from the hydra service if you re using k8s you can then add annotations to your deployment like so

  ```
metadata:
annotations:
prometheus.io/port: "4434"
prometheus.io/path: "/metrics/prometheus"
```
*/
func (a *Client) Prometheus(params *PrometheusParams) (*PrometheusOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPrometheusParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "prometheus",
		Method:             "GET",
		PathPattern:        "/metrics/prometheus",
		ProducesMediaTypes: []string{"plain/text"},
		ConsumesMediaTypes: []string{"application/json", "application/x-www-form-urlencoded"},
		Schemes:            []string{"http", "https"},
		Params:             params,
		Reader:             &PrometheusReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*PrometheusOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for prometheus: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  UpdateIdentity updates an identity

  This endpoint updates an identity. It is NOT possible to set an identity's credentials (password, ...)
using this method! A way to achieve that will be introduced in the future.

The full identity payload (except credentials) is expected. This endpoint does not support patching.

Learn how identities work in [ORY Kratos' User And Identity Model Documentation](https://www.ory.sh/docs/next/kratos/concepts/identity-user-model).
*/
func (a *Client) UpdateIdentity(params *UpdateIdentityParams) (*UpdateIdentityOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUpdateIdentityParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "updateIdentity",
		Method:             "PUT",
		PathPattern:        "/identities/{id}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http", "https"},
		Params:             params,
		Reader:             &UpdateIdentityReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*UpdateIdentityOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for updateIdentity: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
