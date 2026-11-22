package secrets

import (
	"log/slog"

	"gopkg.in/yaml.v3"
)

// SourceBuilder builds sources that share one AWS client per region, for a
// caller that builds many sources at run time.
type SourceBuilder struct {
	registry sourceBuilderRegistry
}

// NewSourceBuilder returns a SourceBuilder.
func NewSourceBuilder(logger *slog.Logger) *SourceBuilder {
	return &SourceBuilder{registry: defaultRegistry(logger)}
}

// Build validates node, a source config as BuildSource takes it, and returns
// its source.
func (b *SourceBuilder) Build(node yaml.Node) (Source, error) {
	return resolveSource(b.registry, node)
}
