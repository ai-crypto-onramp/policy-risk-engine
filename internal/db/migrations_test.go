package db

import (
	"testing"

	"github.com/golang-migrate/migrate/v4/source/file"
)

func TestMigrationsReadable(t *testing.T) {
	f := &file.File{}
	drv, err := f.Open("file://../../migrations")
	if err != nil {
		t.Fatalf("open source: %v", err)
	}
	defer drv.Close()

	v, err := drv.First()
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	for {
		if _, _, err := drv.ReadUp(v); err != nil {
			t.Fatalf("read up %d: %v", v, err)
		}
		if _, _, err := drv.ReadDown(v); err != nil {
			t.Fatalf("read down %d: %v", v, err)
		}
		nv, err := drv.Next(v)
		if err != nil {
			break
		}
		v = nv
	}
}