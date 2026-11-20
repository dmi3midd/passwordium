package passwordium

// CreateOption configures Create. Options that only make sense for Open
// (such as WithMaxArgon2Params) do not implement CreateOption and are rejected at compile time.
type CreateOption interface {
	applyCreate(*createConfig)
}

// OpenOption configures Open. Options that only make sense for Create
// (such as WithArgon2Params or WithOverwrite) do not implement OpenOption and are rejected at compile time.
type OpenOption interface {
	applyOpen(*openConfig)
}

// CreateOpenOption is an option accepted by both Create and Open.
type CreateOpenOption interface {
	CreateOption
	OpenOption
}

type createConfig struct {
	argon2Params    Argon2Params
	allowWeakArgon2 bool
	overwrite       bool
	autoSave        bool
}

type openConfig struct {
	hasMaxArgon2    bool
	maxArgon2Params Argon2Params
	autoSave        bool
}

func defaultCreateConfig() createConfig {
	return createConfig{argon2Params: DefaultArgon2Params()}
}

type createOptionFunc func(*createConfig)

func (f createOptionFunc) applyCreate(cfg *createConfig) { f(cfg) }

type openOptionFunc func(*openConfig)

func (f openOptionFunc) applyOpen(cfg *openConfig) { f(cfg) }

type autoSaveOption bool

func (o autoSaveOption) applyCreate(cfg *createConfig) { cfg.autoSave = bool(o) }
func (o autoSaveOption) applyOpen(cfg *openConfig)     { cfg.autoSave = bool(o) }

// WithArgon2Params overrides the default Argon2id parameters when creating a vault.
// Create rejects parameters with MemoryKiB below 16 MiB (16384 KiB). Use Argon2ParamsMiB
// to avoid KiB/MiB unit mistakes.
func WithArgon2Params(params Argon2Params) CreateOption {
	return createOptionFunc(func(cfg *createConfig) {
		cfg.argon2Params = params
		cfg.allowWeakArgon2 = false
	})
}

// withUnsafeArgon2Params bypasses the Create memory floor. It is unexported and
// intended only for fast in-package unit tests.
func withUnsafeArgon2Params(params Argon2Params) CreateOption {
	return createOptionFunc(func(cfg *createConfig) {
		cfg.argon2Params = params
		cfg.allowWeakArgon2 = true
	})
}

// WithOverwrite controls whether Create may replace an existing vault in Storage.
// By default Create refuses and returns ErrAlreadyExists.
func WithOverwrite(enabled bool) CreateOption {
	return createOptionFunc(func(cfg *createConfig) {
		cfg.overwrite = enabled
	})
}

// WithMaxArgon2Params sets the upper bounds on Argon2id parameters that Open will
// execute from an untrusted header. The combined work limit becomes max.Time * max.MemoryKiB.
// Headers exceeding the limits are rejected with ErrInvalidArgon2Params before any
// key derivation runs. Without this option, DefaultMaxArgon2Params limits apply.
func WithMaxArgon2Params(max Argon2Params) OpenOption {
	return openOptionFunc(func(cfg *openConfig) {
		cfg.hasMaxArgon2 = true
		cfg.maxArgon2Params = max
	})
}

// WithAutoSave enables or disables automatic persistence to Storage after Put, Delete, and DeleteContext.
func WithAutoSave(enabled bool) CreateOpenOption {
	return autoSaveOption(enabled)
}
