package broker

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"text/template"

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
	// alloweedUsersKey is the key in the config file for the users that are allowed to access the machine.
	allowedUsersKey = "allowed_users"
	// alloweedUsersKey is the key in the config file for the users that are allowed to access the machine.
	ownerKey = "owner"
	// homeDirKey is the key in the config file for the home directory prefix.
	homeDirKey = "home_base_dir"
	// SSHSuffixKey is the key in the config file for the SSH allowed suffixes.
	sshSuffixesKey = "ssh_allowed_suffixes"

	// AllUsersKey is the key for allowing access to all users.
	AllUsersKey = "ALL"
	// OwnerUserKey is the key for allowing access to the owner.
	OwnerUserKey = "OWNER"
)

func getDropInFiles(cfgPath string) ([]any, error) {
	// Check if a .d directory exists and return the paths to the files in it.
	dropInDir := cfgPath + ".d"
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

func parseUsersSection(cfg *userConfig, users *ini.Section) {
	if users == nil {
		// The default behavior is to allow only the owner
		cfg.allowedUsers = make(map[string]bool)
		cfg.allowedUsers[OwnerUserKey] = true
		return
	}

	cfg.homeBaseDir = users.Key(homeDirKey).String()
	cfg.allowedSSHSuffixes = strings.Split(users.Key(sshSuffixesKey).String(), ",")
	// We need to differentiate unset owner from empty owner.
	// - Unset means that the owner will be autoregistered
	// - Empty means that there is no owner
	if users.HasKey(ownerKey) {
		o := users.Key(ownerKey).String()
		cfg.owner = &o
	}

	if cfg.allowedUsers == nil {
		cfg.allowedUsers = make(map[string]bool)
	}

	for _, user := range users.Key(allowedUsersKey).Strings(",") {
		cfg.allowedUsers[user] = true
	}

	if len(cfg.allowedUsers) == 0 {
		// The default behavior is to allow only the owner
		cfg.allowedUsers[OwnerUserKey] = true
	}
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

	parseUsersSection(&cfg, iniCfg.Section(usersSection))

	return cfg, nil
}

func (uc *userConfig) IsUserAllowed(user string) bool {
	r, ok := uc.allowedUsers[user]
	if !ok {
		return false
	}
	return r
}

func (uc *userConfig) AllUsersAllowed() bool {
	return uc.IsUserAllowed(AllUsersKey)
}

func (uc *userConfig) OwnerUserAllowed() bool {
	return uc.IsUserAllowed(OwnerUserKey)
}

func (uc *userConfig) Owner() *string {
	return uc.owner
}

func (uc *userConfig) OwnerIsUnset() bool {
	return uc.owner == nil
}

func (uc *userConfig) PersistOwner(cfgPath, userName string) error {
	uc.owner = &userName
	p := filepath.Join(getDropInDir(cfgPath), ownerRegistrationConfigPath)

	templateName := strings.SplitN(ownerRegistrationConfigTemplate, "/", 2)[1]
	t, err := template.New(templateName).ParseFS(ownerRegistrationConfig, ownerRegistrationConfigTemplate)
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to open autoregastration template: %v", err))
		return err
	}

	f, err := os.Create(p)
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to create owner registration file: %v", err))
		return err
	}

	err = t.Execute(f, templateEnv{Owner: *uc.owner})
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to write owner registration file: %v", err))
		return err
	}

	return nil
}
