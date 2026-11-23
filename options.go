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

// ExportOption configures Vault.Export.
type ExportOption interface {
	applyExport(*exportConfig)
}

// CreateExportOption is an option accepted by both Create and Vault.Export.
type CreateExportOption interface {
	CreateOption
	ExportOption
}

// ImportOption configures Vault.Import.
type ImportOption interface {
	applyImport(*importConfig)
}

// OpenImportOption is an option accepted by both Open and Vault.Import.
type OpenImportOption interface {
	OpenOption
	ImportOption
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
	hasMaxWork      bool
	maxArgon2Work   uint64
	autoSave        bool
}

type exportConfig struct {
	hasPassword     bool
	password        []byte
	hasArgon2Params bool
	argon2Params    Argon2Params
	allowWeakArgon2 bool
	overwrite       bool
}

type importConfig struct {
	conflictPolicy ConflictPolicy
	openOpts       []OpenOption
}

func defaultCreateConfig() createConfig {
	return createConfig{argon2Params: DefaultArgon2Params()}
}

func defaultImportConfig() importConfig {
	return importConfig{conflictPolicy: ConflictKeepNewer}
}

type exportOptionFunc func(*exportConfig)

func (f exportOptionFunc) applyExport(cfg *exportConfig) { f(cfg) }

type importOptionFunc func(*importConfig)

func (f importOptionFunc) applyImport(cfg *importConfig) { f(cfg) }

type autoSaveOption bool

func (o autoSaveOption) applyCreate(cfg *createConfig) { cfg.autoSave = bool(o) }
func (o autoSaveOption) applyOpen(cfg *openConfig)     { cfg.autoSave = bool(o) }

type argon2ParamsOption struct {
	params    Argon2Params
	allowWeak bool
}

func (o argon2ParamsOption) applyCreate(cfg *createConfig) {
	cfg.argon2Params = o.params
	cfg.allowWeakArgon2 = o.allowWeak
}

func (o argon2ParamsOption) applyExport(cfg *exportConfig) {
	cfg.hasArgon2Params = true
	cfg.argon2Params = o.params
	cfg.allowWeakArgon2 = o.allowWeak
}

type overwriteOption bool

func (o overwriteOption) applyCreate(cfg *createConfig) { cfg.overwrite = bool(o) }
func (o overwriteOption) applyExport(cfg *exportConfig) { cfg.overwrite = bool(o) }

type maxArgon2ParamsOption struct {
	max Argon2Params
}

func (o maxArgon2ParamsOption) applyOpen(cfg *openConfig) {
	cfg.hasMaxArgon2 = true
	cfg.maxArgon2Params = o.max
}

func (o maxArgon2ParamsOption) applyImport(cfg *importConfig) {
	cfg.openOpts = append(cfg.openOpts, o)
}

type maxArgon2WorkOption uint64

func (o maxArgon2WorkOption) applyOpen(cfg *openConfig) {
	cfg.hasMaxWork = true
	cfg.maxArgon2Work = uint64(o)
}

func (o maxArgon2WorkOption) applyImport(cfg *importConfig) {
	cfg.openOpts = append(cfg.openOpts, o)
}

// WithArgon2Params overrides the default Argon2id parameters when creating or re-keying
// an exported vault. Create and Export reject parameters with MemoryKiB below 16 MiB
// (16384 KiB) or exceeding DefaultMaxArgon2Params limits (Time=16, Memory=512 MiB,
// Threads=16, Time*Memory<=2 GiB-passes). When passed to Vault.Export, WithExportPassword
// must also be provided. Use Argon2ParamsMiB to avoid KiB/MiB unit mistakes.
func WithArgon2Params(params Argon2Params) CreateExportOption {
	return argon2ParamsOption{params: params, allowWeak: false}
}

// withUnsafeArgon2Params bypasses the Create/Export memory floor. It is unexported and
// intended only for fast in-package unit tests.
func withUnsafeArgon2Params(params Argon2Params) CreateExportOption {
	return argon2ParamsOption{params: params, allowWeak: true}
}

// WithOverwrite controls whether Create or Vault.Export may replace an existing vault
// in the destination Storage. By default both refuse and return ErrAlreadyExists.
func WithOverwrite(enabled bool) CreateExportOption {
	return overwriteOption(enabled)
}

// WithExportPassword re-encrypts the exported vault under a new masterPassword and a
// freshly generated 32-byte random salt. Without this option, Vault.Export writes an
// encrypted snapshot using the active vault's current key hierarchy and header parameters.
//
// WithExportPassword does not mutate masterPassword; callers should zero masterPassword
// (for example, via clear(masterPassword)) once Export returns.
func WithExportPassword(masterPassword []byte) ExportOption {
	return exportOptionFunc(func(cfg *exportConfig) {
		cfg.hasPassword = true
		cfg.password = masterPassword
	})
}

// WithConflictPolicy sets the conflict resolution strategy used by Vault.Import when
// an imported entry ID already exists in the destination vault. Defaults to ConflictKeepNewer.
func WithConflictPolicy(policy ConflictPolicy) ImportOption {
	return importOptionFunc(func(cfg *importConfig) {
		cfg.conflictPolicy = policy
	})
}

// WithMaxArgon2Params sets the upper bounds on Argon2id parameters that Open or
// Vault.Import will execute from an untrusted header. When max.Time and max.MemoryKiB
// do not exceed DefaultMaxArgon2Params, the default 2 GiB-passes work limit continues
// to apply (unless overridden via WithMaxArgon2Work); when either bound is raised above
// default, the combined work limit becomes max.Time * max.MemoryKiB.
// Headers exceeding the limits are rejected with ErrInvalidArgon2Params before any
// key derivation runs. Without this option, DefaultMaxArgon2Params limits apply.
func WithMaxArgon2Params(max Argon2Params) OpenImportOption {
	return maxArgon2ParamsOption{max: max}
}

// WithMaxArgon2Work sets an explicit upper bound on uint64(Time) * uint64(MemoryKiB)
// accepted by Open or Vault.Import before running Argon2id. Passing 0 disables the
// product check while keeping per-parameter bounds enforced.
func WithMaxArgon2Work(maxWorkKiBPasses uint64) OpenImportOption {
	return maxArgon2WorkOption(maxWorkKiBPasses)
}

// WithAutoSave enables or disables automatic persistence to Storage after Put, Delete,
// DeleteContext, and Import.
func WithAutoSave(enabled bool) CreateOpenOption {
	return autoSaveOption(enabled)
}
