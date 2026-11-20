package passwordium

// Option configures a Vault during Create or Open.
type Option func(*vaultConfig)

type vaultConfig struct {
	argon2Params Argon2Params
	autoSave     bool
}

func defaultVaultConfig() vaultConfig {
	return vaultConfig{
		argon2Params: DefaultArgon2Params(),
	}
}

// WithArgon2Params overrides the default Argon2id parameters when creating a vault.
func WithArgon2Params(params Argon2Params) Option {
	return func(cfg *vaultConfig) {
		cfg.argon2Params = params
	}
}

// WithAutoSave enables or disables automatic persistence to Storage after Put and Delete.
func WithAutoSave(enabled bool) Option {
	return func(cfg *vaultConfig) {
		cfg.autoSave = enabled
	}
}
