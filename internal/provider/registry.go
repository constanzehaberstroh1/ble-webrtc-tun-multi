package provider

import "sync"

var (
	factoriesMu sync.RWMutex
	factories   = make(map[ProviderType]ClientFactory)
)

// Register registers a client factory for a specific provider type.
func Register(factory ClientFactory) {
	factoriesMu.Lock()
	defer factoriesMu.Unlock()
	factories[factory.Type()] = factory
}

// GetFactory retrieves a registered factory for a provider type.
func GetFactory(pt ProviderType) (ClientFactory, bool) {
	factoriesMu.RLock()
	defer factoriesMu.RUnlock()
	f, ok := factories[pt]
	return f, ok
}

// AllTypes returns a list of all registered provider types.
func AllTypes() []ProviderType {
	factoriesMu.RLock()
	defer factoriesMu.RUnlock()
	types := make([]ProviderType, 0, len(factories))
	for t := range factories {
		types = append(types, t)
	}
	return types
}
