package sessionswap

import (
	"fmt"
	"log/slog"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform"
)

// Name is the transform's name in the config.
const Name = "session_swap"

// Provider builds the ports for one backend from the transform's config
// block. The transform sets Options.Name and Options.Logger itself.
type Provider func(node yaml.Node, logger *slog.Logger) (Options, error)

var (
	providersMu sync.RWMutex
	providers   = make(map[string]Provider)
)

// RegisterProvider makes a backend available as `provider: <name>`.
// Typically called from init() in the provider's package.
func RegisterProvider(name string, p Provider) {
	providersMu.Lock()
	defer providersMu.Unlock()
	providers[name] = p
}

func init() {
	transform.Register(Name, factory)
}

func factory(node yaml.Node, logger *slog.Logger) (transform.Transformer, error) {
	var hint struct {
		Provider string `yaml:"provider"`
	}
	if err := node.Decode(&hint); err != nil {
		return nil, fmt.Errorf("parsing %s config: %w", Name, err)
	}
	providersMu.RLock()
	provider, ok := providers[hint.Provider]
	providersMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%s: unknown provider %q", Name, hint.Provider)
	}
	opts, err := provider(node, logger)
	if err != nil {
		return nil, fmt.Errorf("%s: provider %s: %w", Name, hint.Provider, err)
	}
	if err := startMetrics(); err != nil {
		return nil, fmt.Errorf("%s: %w", Name, err)
	}
	opts.Name = Name
	opts.Logger = logger
	return New(opts), nil
}
