package fourbyte
import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)
type Database struct {
	embedded   map[string]string
	custom     map[string]string
	customPath string
}
func newEmpty() *Database {
	return &Database{
		embedded: make(map[string]string),
		custom:   make(map[string]string),
	}
}
func New() (*Database, error) {
	return NewWithFile("")
}
func NewFromFile(path string) (*Database, error) {
	raw, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer raw.Close()
	db := newEmpty()
	if err := json.NewDecoder(raw).Decode(&db.embedded); err != nil {
		return nil, err
	}
	return db, nil
}
func NewWithFile(path string) (*Database, error) {
	db := &Database{make(map[string]string), make(map[string]string), path}
	db.customPath = path
	blob, err := Asset("4byte.json")
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(blob, &db.embedded); err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); err == nil {
		if blob, err = ioutil.ReadFile(path); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(blob, &db.custom); err != nil {
			return nil, err
		}
	}
	return db, nil
}
func (db *Database) Size() (int, int) {
	return len(db.embedded), len(db.custom)
}
func (db *Database) Selector(id []byte) (string, error) {
	if len(id) < 4 {
		return "", fmt.Errorf("expected 4-byte id, got %d", len(id))
	}
	sig := hex.EncodeToString(id[:4])
	if selector, exists := db.embedded[sig]; exists {
		return selector, nil
	}
	if selector, exists := db.custom[sig]; exists {
		return selector, nil
	}
	return "", fmt.Errorf("signature %v not found", sig)
}
func (db *Database) AddSelector(selector string, data []byte) error {
	if len(data) < 4 {
		return nil
	}
	if _, err := db.Selector(data[:4]); err == nil {
		return nil
	}
	db.custom[hex.EncodeToString(data[:4])] = selector
	if db.customPath == "" {
		return nil
	}
	blob, err := json.Marshal(db.custom)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(db.customPath, blob, 0600)
}
