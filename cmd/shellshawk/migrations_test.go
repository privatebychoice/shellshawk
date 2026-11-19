package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// releasedMigrations pins the SHA-256 of every migration that may already
// be applied to a database. The server refuses to start if an applied
// migration's SQL changes (even a comment), so never edit one: add a new
// version instead, then add its checksum here.
var releasedMigrations = map[string]string{
	"chat/1":                             "7f5d4611b2ae7751835b0d6c98686c6c149eadf0fa3b49656db8a432c102f8a1",
	"chat/2":                             "2ef871e6eec171036507f2ec33c5f8b0ef34f7f6873271d9e2600565ef4ff2af",
	"conferences/1":                      "647a386701537f4c3af107735db298a5bb154a7a0c5dd6d8b0e33a61e0c8b043",
	"conferences/2":                      "e71189ff9d07a954e81f32ed87cd8deeafe283a6e039c5c7aacb46a9abf617c9",
	"contacts/1":                         "7b06afb0e44bfa2368f93e2f8e8a0526f92d478598575d62656c89a4eb29d3f8",
	"core/0001_system_settings.sql":      "50878a8a000dbc0dadc14fe6906c3b1bde20eb9d37ddb3c58ec363bd04f05175",
	"core/0002_accounts.sql":             "89d5682ad4a220749990de9b763ad50923891ce367827c4b8b8e08c7403737f1",
	"core/0003_user_prefs.sql":           "be3a17eaaac02978c3da675814a68ac0e750f3f79adf81f4a44b3c83cef1c530",
	"core/0004_menus_plugins.sql":        "50dc21d0cb07816377b29222e6371bb49e040be64e640c8742216c3107d3e08c",
	"core/0005_privacy.sql":              "abdf24d6be4bf57784fe486039e395b46880bb335da1892bf355f61bda3248d5",
	"core/0006_web.sql":                  "eddb1fe1c4553ef33730955923e2d30765a2b42d9887af0f1935235c712e0f78",
	"core/0007_logout_entry.sql":         "78190a52e5a186521dead9d741ade38c7fd039fddb35fde4cfeab93c671236d0",
	"core/0008_web_session_activity.sql": "bffe80d841ec72b3524c96ce7a783982cc583634759bcc5f4e05a70ec472c371",
	"core/0009_transitions.sql":          "4505640bd8955853269e6f3037b34602bf13dd079995324725f2ef80115b4468",
	"core/0010_notifications.sql":        "ce0bd9289d527e05cff5a4230b87f6c13770c45885cbd3c1e5a24c1642f67edf",
	"messages/1":                         "707e773939df8ae3387875601608315023fdc67b84e8407c570b069d69a9ea46",
	"motd/1":                             "22a08fd572c12f6134c500c0eac866db860218e7d65e0f3843d725bf5e837ff2",
	"polls/1":                            "167f6165706151b216eaaca7367bd83b06eb3fbed2bc9927c4b97217ef4831c8",
	"wall/1":                             "b310db47ff17c2a50c1c93ebebf8aa225693c1a1326439af3760b697f87664ff",
}

func migrationSums(t *testing.T) map[string]string {
	t.Helper()
	got := map[string]string{}
	files, err := filepath.Glob("../../internal/store/migrations/*.sql")
	if err != nil || len(files) == 0 {
		t.Fatalf("core migrations not found: %v", err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		got["core/"+filepath.Base(f)] = hex.EncodeToString(sum[:])
	}
	for _, p := range installedPlugins() {
		m := p.Manifest()
		for _, mg := range m.Migrations {
			sum := sha256.Sum256([]byte(mg.SQL))
			got[fmt.Sprintf("%s/%d", m.ID, mg.Version)] = hex.EncodeToString(sum[:])
		}
	}
	return got
}

func TestReleasedMigrationsUnchanged(t *testing.T) {
	got := migrationSums(t)
	for key, want := range releasedMigrations {
		if sum, ok := got[key]; !ok {
			t.Errorf("released migration %s was removed", key)
		} else if sum != want {
			t.Errorf("released migration %s was edited: servers that applied it will refuse to start. Revert it and add a new migration version instead.", key)
		}
	}
	var missing []string
	for key, sum := range got {
		if _, ok := releasedMigrations[key]; !ok {
			missing = append(missing, fmt.Sprintf("\t%q: %q,", key, sum))
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("new migrations: once final, pin them in releasedMigrations:\n%s", strings.Join(missing, "\n"))
	}
}
