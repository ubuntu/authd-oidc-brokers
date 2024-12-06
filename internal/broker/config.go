package broker

import (
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/ini.v1"
)

// Configuration sections and keys.
const (
	// oidcSection is the section name in the config file for the OIDC specific configuration.
	oidcSection = "oidc"
	// issuerKey is the key in the config file for the issuer.
	issuerKey = "issuer"
	// clientIDKey is the key in the config file for the client ID.
	clientIDKey = "client_id"
	// clientSecret is the optional client secret for this client.
	clientSecret = "client_secret"

	// usersSection is the section name in the config file for the users and broker specific configuration.
	usersSection = "users"
	// allowedUsersKey is the key in the config file for the users that are allowed to access the machine.
	allowedUsersKey = "allowed_users"
	// ownerKey is the key in the config file for the owner of the machine.
	ownerKey = "owner"
	// homeDirKey is the key in the config file for the home directory prefix.
	homeDirKey = "home_base_dir"
	// SSHSuffixKey is the key in the config file for the SSH allowed suffixes.
	sshSuffixesKey = "ssh_allowed_suffixes"

	// AllUsersKeyword is the keyword for the `allowed_users` key that allows access to all users.
	AllUsersKeyword = "ALL"
	// OwnerUserKeyword is the keyword for the `allowed_users` key that allows access to the owner.
	OwnerUserKeyword = "OWNER"

	// ownerAutoRegistrationConfigPath is the name of the file that will be auto-generated to register the owner.
	ownerAutoRegistrationConfigPath     = "20-owner-autoregistration.conf"
	ownerAutoRegistrationConfigTemplate = "templates/20-owner-autoregistration.conf.tmpl"
)

var (
	//go:embed templates/20-owner-autoregistration.conf.tmpl
	ownerAutoRegistrationConfig embed.FS
)

type templateEnv struct {
	Owner string
}

type userConfig struct {
	clientID     string
	clientSecret string
	issuerURL    string

	allowedUsers          map[string]struct{}
	allUsersAllowed       bool
	ownerAllowed          bool
	firstUserBecomesOwner bool
	owner                 string
	homeBaseDir           string
	allowedSSHSuffixes    []string
}

// GetDropInDir takes the broker configuration path and returns the drop in dir path.
func GetDropInDir(cfgPath string) string {
	return cfgPath + ".d"
}

func getDropInFiles(cfgPath string) ([]any, error) {
	// Check if a .d directory exists and return the paths to the files in it.
	dropInDir := GetDropInDir(cfgPath)
	files, err := os.ReadDir(dropInDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var dropInFiles []any
	// files is empty if the directory does not exist
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		dropInFiles = append(dropInFiles, filepath.Join(dropInDir, file.Name()))
	}

	return dropInFiles, nil
}

func populateUsersConfig(cfg *userConfig, users *ini.Section) {
	if users == nil {
		// The default behavior is to allow only the owner
		cfg.ownerAllowed = true
		cfg.firstUserBecomesOwner = true
		return
	}

	cfg.homeBaseDir = users.Key(homeDirKey).String()
	cfg.allowedSSHSuffixes = strings.Split(users.Key(sshSuffixesKey).String(), ",")

	if cfg.allowedUsers == nil {
		cfg.allowedUsers = make(map[string]struct{})
	}

	allowedUsers := users.Key(allowedUsersKey).Strings(",")
	if len(allowedUsers) == 0 {
		allowedUsers = append(allowedUsers, OwnerUserKeyword)
	}

	for _, user := range allowedUsers {
		if user == AllUsersKeyword {
			cfg.allUsersAllowed = true
			continue
		}
		if user == OwnerUserKeyword {
			cfg.ownerAllowed = true
			if !users.HasKey(ownerKey) {
				// If owner is unset, then the first user becomes owner
				cfg.firstUserBecomesOwner = true
			}
			continue
		}

		cfg.allowedUsers[user] = struct{}{}
	}

	// We need to read the owner key after we call HasKey, because the key is created
	// when we call the "Key" function and we can't distinguish between empty and unset.
	cfg.owner = users.Key(ownerKey).String()
}

// parseConfigFile parses the config file and returns a map with the configuration keys and values.
func parseConfigFile(cfgPath string) (userConfig, error) {
	cfg := userConfig{}

	dropInFiles, err := getDropInFiles(cfgPath)
	if err != nil {
		return cfg, err
	}

	iniCfg, err := ini.Load(cfgPath, dropInFiles...)
	if err != nil {
		return cfg, err
	}

	// Check if any of the keys still contain the placeholders.
	for _, section := range iniCfg.Sections() {
		for _, key := range section.Keys() {
			if strings.Contains(key.Value(), "<") && strings.Contains(key.Value(), ">") {
				err = errors.Join(err, fmt.Errorf("found invalid character in section %q, key %q", section.Name(), key.Name()))
			}
		}
	}
	if err != nil {
		return cfg, fmt.Errorf("config file has invalid values, did you edit the file %q?\n%w", cfgPath, err)
	}

	oidc := iniCfg.Section(oidcSection)
	if oidc != nil {
		cfg.issuerURL = oidc.Key(issuerKey).String()
		cfg.clientID = oidc.Key(clientIDKey).String()
		cfg.clientSecret = oidc.Key(clientSecret).String()
	}

	populateUsersConfig(&cfg, iniCfg.Section(usersSection))

	return cfg, nil
}

func (uc *userConfig) shouldRegisterOwner() bool {
	return uc.ownerAllowed && uc.firstUserBecomesOwner && uc.owner == ""
}

func (uc *userConfig) registerOwner(cfgPath, userName string) error {
	if cfgPath == "" {
		uc.owner = userName
		uc.firstUserBecomesOwner = false
		return nil
	}

	p := filepath.Join(GetDropInDir(cfgPath), ownerAutoRegistrationConfigPath)

	templateName := filepath.Base(ownerAutoRegistrationConfigTemplate)
	t, err := template.New(templateName).ParseFS(ownerAutoRegistrationConfig, ownerAutoRegistrationConfigTemplate)
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to open autoregistration template: %v", err))
		return err
	}

	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to create owner registration file: %v", err))
		return err
	}
	defer f.Close()

	err = t.Execute(f, templateEnv{Owner: userName})
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to write owner registration file: %v", err))
		return err
	}

	// We set the owner after we create the autoregistration file, so that in case of an error
	// the owner is not updated.
	uc.owner = userName
	uc.firstUserBecomesOwner = false

	return nil
}
