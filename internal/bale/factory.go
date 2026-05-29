package bale

import (
	"errors"

	"github.com/salman/ble-webrtc-tun/internal/provider"
)

func init() {
	provider.Register(&BaleClientFactory{})
}

// BaleClientFactory implements provider.ClientFactory.
type BaleClientFactory struct{}

// NewClient implements provider.ClientFactory
func (f *BaleClientFactory) NewClient(accountData map[string]interface{}) (provider.Client, error) {
	token, ok := accountData["token"].(string)
	if !ok || token == "" {
		return nil, errors.New("missing or invalid 'token' key in accountData for Bale provider")
	}
	return NewBaleClientAdapter(token), nil
}

// NewAuthClient implements provider.ClientFactory
func (f *BaleClientFactory) NewAuthClient() provider.AuthClient {
	return NewBaleAuthAdapter()
}

// Type implements provider.ClientFactory
func (f *BaleClientFactory) Type() provider.ProviderType {
	return provider.ProviderBale
}

// Ensure interface compatibility
var (
	_ provider.ClientFactory = (*BaleClientFactory)(nil)
	_ provider.Client        = (*BaleClientAdapter)(nil)
	_ provider.AuthClient    = (*BaleAuthAdapter)(nil)
)
