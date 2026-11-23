# passwordium

A single-file encrypted vault library in Go for storing sensitive credentials, keys, and notes.

## Usage

```go
package main

import (
 "context"
 "fmt"
 "log"

 "github.com/dmi3midd/passwordium"
)

func main() {
 ctx := context.Background()
 store := passwordium.NewFileStorage("vault.psdm")
 masterPassword := []byte("correct-horse-battery-staple")

 v, err := passwordium.Create(ctx, store, masterPassword)
 if err != nil {
  log.Fatal(err)
 }

 id, err := v.Put(ctx, passwordium.EntryMeta{
  Title:    "GitHub",
  Username: "octocat",
  URL:      "https://github.com",
  Tags:     []string{"dev", "git"},
 }, passwordium.Secret{
  Password: "s3cr3t-password",
  Notes:    "Personal token",
 })
 if err != nil {
  log.Fatal(err)
 }

 if err := v.Save(ctx); err != nil {
  log.Fatal(err)
 }
 if err := v.Close(); err != nil {
  log.Fatal(err)
 }

 opened, err := passwordium.Open(ctx, store, masterPassword)
 if err != nil {
  log.Fatal(err)
 }
 defer opened.Close()

 matches := opened.Search(passwordium.SearchQuery{Query: "github"})
 secret, err := opened.GetSecret(id)
 if err != nil {
  log.Fatal(err)
 }
 fmt.Printf("found=%d password=%s\n", len(matches), secret.Password)
}
```
