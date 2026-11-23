package passwordium

// CreateOption configures vault creation in Create.
//
// Options that only apply to opening an existing vault (such as WithMaxArgon2Params
// or WithMaxArgon2Work) do not implement CreateOption and are rejected at compile time.
// Passing a nil CreateOption to Create is safely ignored.
type CreateOption interface {
	applyCreate(*createConfig)
}

// OpenOption configures vault loading and pre-KDF resource limits in Open.
//
// Options that only apply to creating or exporting a vault (such as WithArgon2Params
// or WithOverwrite) do not implement OpenOption and are rejected at compile time.
// Passing a nil OpenOption to Open is safely ignored.
type OpenOption interface {
	applyOpen(*openConfig)
}

// CreateOpenOption is a composite option interface implemented by options that are
// valid for both Create and Open (such as WithAutoSave).
type CreateOpenOption interface {
	CreateOption
	OpenOption
}

// ExportOption configures snapshot creation and optional re-keying in Vault.Export.
// Passing a nil ExportOption to Vault.Export is safely ignored.
type ExportOption interface {
	applyExport(*exportConfig)
}

// CreateExportOption is a composite option interface implemented by options that are
// valid for both Create and Vault.Export (such as WithArgon2Params and WithOverwrite).
type CreateExportOption interface {
	CreateOption
	ExportOption
}

// ImportOption configures conflict resolution and pre-KDF source header limits in Vault.Import.
// Passing a nil ImportOption to Vault.Import is safely ignored.
type ImportOption interface {
	applyImport(*importConfig)
}

// OpenImportOption is a composite option interface implemented by options that are
// valid for both Open and Vault.Import (such as WithMaxArgon2Params and WithMaxArgon2Work).
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

// WithArgon2Params overrides the default Argon2id parameters (DefaultArgon2Params)
// when creating a vault with Create or re-keying an exported vault with Vault.Export.
//
// Create and Vault.Export validate params before running key derivation and return
// ErrInvalidArgon2Params if:
//   - params.MemoryKiB is below the creation floor of 16 MiB (16,384 KiB),
//   - params.Time, params.MemoryKiB, or params.Threads is zero or exceeds DefaultMaxArgon2Params
//     (Time=16, Memory=512 MiB, Threads=16), or
//   - uint64(params.Time) * uint64(params.MemoryKiB) exceeds 2 GiB-passes (2,097,152 KiB-passes).
//
// Enforcing DefaultMaxArgon2Params on creation guarantees that any vault created by
// passwordium can always be opened by Open under its default resource limits.
// When passed to Vault.Export, WithExportPassword must also be provided; otherwise
// Vault.Export returns ErrEmptyPassword. Prefer Argon2ParamsMiB to construct params.
func WithArgon2Params(params Argon2Params) CreateExportOption {
	return argon2ParamsOption{params: params, allowWeak: false}
}

// withUnsafeArgon2Params bypasses the Create/Export memory floor. It is unexported and
// intended only for fast in-package unit tests.
func withUnsafeArgon2Params(params Argon2Params) CreateExportOption {
	return argon2ParamsOption{params: params, allowWeak: true}
}

// WithOverwrite controls whether Create or Vault.Export may overwrite an existing vault
// in the target Storage backend.
//
// By default (enabled == false), both Create and Vault.Export check for an existing
// vault before deriving keys and use atomic exclusive creation (SaveNew) where supported,
// returning ErrAlreadyExists without modifying the existing vault. When enabled is true,
// the newly encrypted vault atomically replaces any existing vault in Storage.
func WithOverwrite(enabled bool) CreateExportOption {
	return overwriteOption(enabled)
}

// WithExportPassword instructs Vault.Export to re-key the exported vault snapshot under
// masterPassword using a freshly generated 32-byte random salt.
//
// When WithExportPassword is supplied, Vault.Export derives a new masterKey, indexKey,
// and secretKey (using the active vault's Argon2id parameters unless overridden via
// WithArgon2Params) and re-encrypts each entry's padded SecretPayload in place as a
// temporary byte slice without allocating immutable Go strings. If masterPassword is
// empty (len(masterPassword) == 0), Vault.Export returns ErrEmptyPassword.
//
// Without this option, Vault.Export writes an encrypted snapshot using the active
// vault's existing salt, Argon2id parameters, and key hierarchy without decrypting
// individual entry secrets.
//
// WithExportPassword retains the slice header of masterPassword in the option value
// and does not mutate its contents; callers should zero masterPassword (for example,
// via clear(masterPassword)) once Vault.Export returns.
func WithExportPassword(masterPassword []byte) ExportOption {
	return exportOptionFunc(func(cfg *exportConfig) {
		cfg.hasPassword = true
		cfg.password = masterPassword
	})
}

// WithConflictPolicy sets the ConflictPolicy used by Vault.Import when an entry ID in
// the source vault already exists in the destination Vault.
//
// If WithConflictPolicy is not provided, Vault.Import defaults to ConflictKeepNewer.
// Passing an unrecognized ConflictPolicy value causes Vault.Import to fail immediately
// with ErrInvalidConflictPolicy before opening the source vault.
func WithConflictPolicy(policy ConflictPolicy) ImportOption {
	return importOptionFunc(func(cfg *importConfig) {
		cfg.conflictPolicy = policy
	})
}

// WithMaxArgon2Params overrides the default upper bounds (DefaultMaxArgon2Params) on
// Argon2id parameters that Open or Vault.Import will accept from an untrusted vault
// header before executing key derivation.
//
// The max parameters must themselves satisfy hard protocol bounds (Time in [1, 100],
// MemoryKiB in [8, 4194304], Threads in [1, 255]); otherwise Open and Vault.Import
// return ErrInvalidArgon2Params immediately.
//
// When max.Time and max.MemoryKiB do not exceed DefaultMaxArgon2Params (Time <= 16 and
// MemoryKiB <= 512 MiB), the default combined work cap of 2 GiB-passes continues to
// apply unless explicitly overridden with WithMaxArgon2Work. When either max.Time or
// max.MemoryKiB is raised above DefaultMaxArgon2Params, the combined work cap defaults
// to uint64(max.Time) * uint64(max.MemoryKiB). Any vault header exceeding these bounds
// is rejected with ErrInvalidArgon2Params prior to running Argon2id.
func WithMaxArgon2Params(max Argon2Params) OpenImportOption {
	return maxArgon2ParamsOption{max: max}
}

// WithMaxArgon2Work sets an explicit upper bound on the combined Argon2id work product
// uint64(Time) * uint64(MemoryKiB) (expressed in KiB-passes) accepted by Open or
// Vault.Import before running key derivation.
//
// Headers whose Time * MemoryKiB exceeds maxWorkKiBPasses are rejected during header
// parsing with ErrInvalidArgon2Params. Passing 0 disables the combined work-product
// check while still enforcing per-parameter bounds (from DefaultMaxArgon2Params or
// WithMaxArgon2Params).
func WithMaxArgon2Work(maxWorkKiBPasses uint64) OpenImportOption {
	return maxArgon2WorkOption(maxWorkKiBPasses)
}

// WithAutoSave enables or disables automatic persistence to the backing Storage after
// every mutating operation on a Vault (Vault.Put, Vault.Delete, Vault.DeleteContext,
// and Vault.Import).
//
// When enabled is true, each mutation immediately serializes, encrypts, and saves the
// updated vault container while holding the Vault's write lock. If the underlying
// Storage save fails (for example, due to I/O error, context cancellation, ErrVaultTooLarge,
// or ErrConcurrentModification), the in-memory mutation and dirty flag are atomically
// rolled back and the error is returned to the caller.
//
// By default (enabled == false), mutations only mark the Vault as dirty in memory until
// Vault.Save or Vault.CloseWithSave is called explicitly.
func WithAutoSave(enabled bool) CreateOpenOption {
	return autoSaveOption(enabled)
}
