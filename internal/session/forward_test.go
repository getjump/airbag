package session

import "testing"

func TestParseForwards(t *testing.T) {
	hosts, fw, err := ParseForwards([]string{"api.github.com", "tcp://127.0.0.1:5432", "tcp://[::1]:6379", "tcp://127.0.0.1:5432"})
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0] != "api.github.com" {
		t.Errorf("hosts %v", hosts)
	}
	if len(fw) != 2 || fw[0] != (Forward{"127.0.0.1", 5432}) || fw[1] != (Forward{"::1", 6379}) {
		t.Errorf("forwards %v", fw)
	}
	if fw[1].String() != "tcp://[::1]:6379" {
		t.Errorf("String %s", fw[1])
	}
	for _, bad := range []string{"tcp://db", "tcp://db:0", "tcp://db:x"} {
		if _, _, err := ParseForwards([]string{bad}); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
