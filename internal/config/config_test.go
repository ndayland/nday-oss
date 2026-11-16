package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"nday.land/nday/internal/config"
)

// Expected values were checked against nday.config.load_dotenv (Python).
func TestLoadDotenvLikePython(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".env")
	content := "# comment\n\n  NDAY_T_A = \"x=1\" \nNDAY_T_B='q'\r\nNOEQUALS\nNDAY_T_C=\"'mixed'\"\n#NDAY_T_D=1\nNDAY_T_E=keep\nNDAY_T_F=\x1fv\x1f\n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NDAY_T_E", "env wins")
	for _, k := range []string{"NDAY_T_A", "NDAY_T_B", "NDAY_T_C", "NDAY_T_D", "NDAY_T_F"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	if err := config.LoadDotenv(p); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"NDAY_T_A": "x=1", "NDAY_T_B": "q", "NDAY_T_C": "mixed", "NDAY_T_E": "env wins", "NDAY_T_F": "v"}
	for k, v := range want {
		if got := os.Getenv(k); got != v {
			t.Errorf("%s = %q want %q", k, got, v)
		}
	}
	if _, ok := os.LookupEnv("NDAY_T_D"); ok {
		t.Error("commented line loaded")
	}
	if err := config.LoadDotenv(filepath.Join(dir, "missing")); err != nil {
		t.Error(err)
	}
}
