package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	clientkeyapp "github.com/chenyme/grok2api/backend/internal/application/clientkey"
	"github.com/chenyme/grok2api/backend/internal/infra/persistence/relational"
	"github.com/chenyme/grok2api/backend/internal/infra/security"
	"gopkg.in/yaml.v3"
)

type configFile struct {
	Secrets struct {
		CredentialEncryptionKey string `yaml:"credentialEncryptionKey"`
	} `yaml:"secrets"`
	Database struct {
		Driver string `yaml:"driver"`
		SQLite struct {
			Path string `yaml:"path"`
		} `yaml:"sqlite"`
	} `yaml:"database"`
}

func main() {
	configPath := flag.String("config", "config.yaml", "path to config.yaml")
	id := flag.Uint64("id", 0, "client key id")
	name := flag.String("name", "", "client key name (alternative to -id)")
	secret := flag.String("secret", "", "new full raw secret (g2a_* or custom)")
	flag.Parse()
	if strings.TrimSpace(*secret) == "" || (*id == 0 && strings.TrimSpace(*name) == "") {
		fmt.Fprintln(os.Stderr, "usage: set_client_secret -config config.yaml (-id N|-name OpenCode) -secret '...'")
		os.Exit(2)
	}
	raw, err := os.ReadFile(*configPath)
	if err != nil {
		fatal(err)
	}
	var cfg configFile
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		fatal(err)
	}
	dbPath := cfg.Database.SQLite.Path
	if dbPath == "" {
		dbPath = "./data/backend.db"
	}
	if !filepath.IsAbs(dbPath) {
		dbPath = filepath.Join(filepath.Dir(*configPath), dbPath)
	}
	cipher, err := security.NewCipher(cfg.Secrets.CredentialEncryptionKey)
	if err != nil {
		fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database, err := relational.OpenSQLite(ctx, dbPath)
	if err != nil {
		fatal(err)
	}
	defer database.Close()
	repo := relational.NewClientKeyRepository(database)
	service := clientkeyapp.NewService(repo, nil, nil, 60, 4, cipher)
	targetID := *id
	if targetID == 0 {
		keys, _, listErr := service.List(ctx, 1, 100, *name, clientkeyapp.ListFilter{})
		if listErr != nil {
			fatal(listErr)
		}
		for _, key := range keys {
			if strings.EqualFold(key.Name, strings.TrimSpace(*name)) {
				targetID = key.ID
				break
			}
		}
		if targetID == 0 {
			fatal(fmt.Errorf("client key name %q not found", *name))
		}
	}
	if err := service.ReplaceSecret(ctx, targetID, *secret); err != nil {
		fatal(err)
	}
	// Verify authenticate path accepts the new secret.
	if _, release, authErr := service.Authenticate(ctx, *secret); authErr != nil {
		fatal(fmt.Errorf("replace ok but authenticate failed: %w", authErr))
	} else if release != nil {
		release()
	}
	fmt.Printf("updated client key id=%d secret_len=%d\n", targetID, len(*secret))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
