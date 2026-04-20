package vulns

import "sync"

type Registry struct {
	mu      sync.RWMutex
	remote  map[string]VulnModule
	static  map[string]StaticModule
}

var Default = &Registry{
	remote: make(map[string]VulnModule),
	static: make(map[string]StaticModule),
}

func RegisterRemote(m VulnModule) {
	Default.mu.Lock()
	defer Default.mu.Unlock()
	Default.remote[m.ID()] = m
}

func RegisterStatic(m StaticModule) {
	Default.mu.Lock()
	defer Default.mu.Unlock()
	Default.static[m.ID()] = m
}

func (r *Registry) AllRemote() []VulnModule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]VulnModule, 0, len(r.remote))
	for _, m := range r.remote {
		out = append(out, m)
	}
	return out
}

func (r *Registry) AllStatic() []StaticModule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]StaticModule, 0, len(r.static))
	for _, m := range r.static {
		out = append(out, m)
	}
	return out
}

func (r *Registry) GetRemote(id string) (VulnModule, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.remote[id]
	return m, ok
}
