package importer

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Store struct {
	root string
}

func NewStore(root string) Store {
	return Store{root: filepath.Join(root, "imports")}
}

func (s Store) Save(record ImportRecord) error {
	if strings.TrimSpace(record.ID) == "" {
		return errors.New("import id is required")
	}
	if err := validateImportID(record.ID); err != nil {
		return err
	}
	now := time.Now().UTC()
	if record.CreatedAt.IsZero() {
		record.CreatedAt = now
	}
	record.UpdatedAt = now
	if err := os.MkdirAll(s.root, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path(record.ID), append(data, '\n'), 0o600)
}

func (s Store) Get(id string) (ImportRecord, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return ImportRecord{}, errors.New("import id is required")
	}
	if err := validateImportID(id); err != nil {
		return ImportRecord{}, err
	}
	data, err := os.ReadFile(s.path(id))
	if err != nil {
		return ImportRecord{}, err
	}
	var record ImportRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return ImportRecord{}, err
	}
	return record, nil
}

func (s Store) List() ([]ImportRecord, error) {
	entries, err := os.ReadDir(s.root)
	if errors.Is(err, os.ErrNotExist) {
		return []ImportRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	var records []ImportRecord
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		record, err := s.Get(strings.TrimSuffix(entry.Name(), ".json"))
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	sort.SliceStable(records, func(i, j int) bool { return records[i].CreatedAt.After(records[j].CreatedAt) })
	return records, nil
}

func (s Store) path(id string) string {
	return filepath.Join(s.root, id+".json")
}

func validateImportID(id string) error {
	if id == "" || strings.Contains(id, "..") || strings.ContainsAny(id, `/\`) {
		return errors.New("invalid import id")
	}
	return nil
}
