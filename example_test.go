package passwordium_test

import (
	"context"
	"fmt"
	"log"

	"github.com/dmi3midd/passwordium"
)

func ExampleCreate() {
	ctx := context.Background()
	store := passwordium.NewMemoryStorage()
	masterPassword := []byte("correct-horse-battery-staple")
	defer clear(masterPassword)

	v, err := passwordium.Create(ctx, store, masterPassword,
		passwordium.WithArgon2Params(passwordium.Argon2ParamsMiB(1, 16, 1)),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer v.Close()

	id, err := v.Put(ctx, passwordium.EntryMeta{
		Title:    "GitHub",
		Username: "octocat",
		URL:      "https://github.com",
		Tags:     []string{"dev", "git"},
	}, passwordium.Secret{
		Password: "s3cr3t-password",
	})
	if err != nil {
		log.Fatal(err)
	}
	if err := v.CloseWithSave(ctx); err != nil {
		log.Fatal(err)
	}

	reopened, err := passwordium.Open(ctx, store, masterPassword)
	if err != nil {
		log.Fatal(err)
	}
	defer reopened.Close()

	sec, err := reopened.GetSecret(id)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(reopened.Len(), sec.Password)
	// Output:
	// 1 s3cr3t-password
}

func ExampleVault_Search() {
	ctx := context.Background()
	store := passwordium.NewMemoryStorage()
	pass := []byte("search-example-password")
	defer clear(pass)

	v, err := passwordium.Create(ctx, store, pass,
		passwordium.WithArgon2Params(passwordium.Argon2ParamsMiB(1, 16, 1)),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer v.Close()

	_, _ = v.Put(ctx, passwordium.EntryMeta{
		Title:    "GitHub",
		Username: "octocat",
		Tags:     []string{"Dev", "Work"},
	}, passwordium.Secret{Password: "pw1"})
	_, _ = v.Put(ctx, passwordium.EntryMeta{
		Title:    "Personal Mail",
		Username: "alice",
		Tags:     []string{"Personal"},
	}, passwordium.Secret{Password: "pw2"})

	matches := v.Search(passwordium.SearchQuery{
		Query: "git",
		Tags:  []string{"work"},
	})
	for _, m := range matches {
		fmt.Println(m.Title, m.Username)
	}
	// Output:
	// GitHub octocat
}

func ExampleVault_Export() {
	ctx := context.Background()
	primaryStore := passwordium.NewMemoryStorage()
	primaryPass := []byte("primary-vault-password")
	defer clear(primaryPass)

	kdfOpt := passwordium.WithArgon2Params(passwordium.Argon2ParamsMiB(1, 16, 1))
	v, err := passwordium.Create(ctx, primaryStore, primaryPass, kdfOpt)
	if err != nil {
		log.Fatal(err)
	}
	defer v.Close()

	_, err = v.Put(ctx, passwordium.EntryMeta{
		ID:    "prod-db",
		Title: "Production DB",
	}, passwordium.Secret{Password: "db-secret"})
	if err != nil {
		log.Fatal(err)
	}

	backupStore := passwordium.NewMemoryStorage()
	exportPass := []byte("transfer-export-password")
	defer clear(exportPass)

	if err := v.Export(ctx, backupStore,
		passwordium.WithExportPassword(exportPass),
		kdfOpt,
	); err != nil {
		log.Fatal(err)
	}

	exported, err := passwordium.Open(ctx, backupStore, exportPass)
	if err != nil {
		log.Fatal(err)
	}
	defer exported.Close()

	sec, err := exported.GetSecret("prod-db")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(sec.Password)
	// Output:
	// db-secret
}

func ExampleVault_Import() {
	ctx := context.Background()
	kdfOpt := passwordium.WithArgon2Params(passwordium.Argon2ParamsMiB(1, 16, 1))

	srcStore := passwordium.NewMemoryStorage()
	srcPass := []byte("source-vault-password")
	defer clear(srcPass)

	srcVault, err := passwordium.Create(ctx, srcStore, srcPass, kdfOpt, passwordium.WithAutoSave(true))
	if err != nil {
		log.Fatal(err)
	}
	_, _ = srcVault.Put(ctx, passwordium.EntryMeta{ID: "entry-1", Title: "Imported"}, passwordium.Secret{Password: "from-source"})
	_ = srcVault.Close()

	dstStore := passwordium.NewMemoryStorage()
	dstPass := []byte("destination-vault-password")
	defer clear(dstPass)

	dstVault, err := passwordium.Create(ctx, dstStore, dstPass, kdfOpt)
	if err != nil {
		log.Fatal(err)
	}
	defer dstVault.Close()

	res, err := dstVault.Import(ctx, srcStore, srcPass,
		passwordium.WithConflictPolicy(passwordium.ConflictKeepNewer),
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("added=%d updated=%d skipped=%d\n", res.Added, res.Updated, res.Skipped)
	// Output:
	// added=1 updated=0 skipped=0
}

func ExampleSecret_String() {
	sec := passwordium.Secret{
		Password: "super-secret-password",
		Notes:    "recovery phrase",
	}
	fmt.Printf("%s | %#v\n", sec, sec)
	// Output:
	// passwordium.Secret{REDACTED} | passwordium.Secret{REDACTED}
}

func ExampleArgon2ParamsMiB() {
	params := passwordium.Argon2ParamsMiB(3, 64, 2)
	fmt.Printf("Time=%d MemoryKiB=%d Threads=%d\n", params.Time, params.MemoryKiB, params.Threads)
	// Output:
	// Time=3 MemoryKiB=65536 Threads=2
}
