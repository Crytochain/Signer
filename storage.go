package storage
import "errors"
var (
	ErrZeroKey = errors.New("0-length key")
	ErrNotFound = errors.New("not found")
)
type Storage interface {
	Put(key, value string)
	Get(key string) (string, error)
	Del(key string)
}
type EphemeralStorage struct {
	data map[string]string
}
func (s *EphemeralStorage) Put(key, value string) {
	if len(key) == 0 {
		return
	}
	s.data[key] = value
}
func (s *EphemeralStorage) Get(key string) (string, error) {
	if len(key) == 0 {
		return "", ErrZeroKey
	}
	if v, ok := s.data[key]; ok {
		return v, nil
	}
	return "", ErrNotFound
}
func (s *EphemeralStorage) Del(key string) {
	delete(s.data, key)
}
func NewEphemeralStorage() Storage {
	s := &EphemeralStorage{
		data: make(map[string]string),
	}
	return s
}
type NoStorage struct{}
func (s *NoStorage) Put(key, value string) {}
func (s *NoStorage) Del(key string)        {}
func (s *NoStorage) Get(key string) (string, error) {
	return "", errors.New("missing key, I probably forgot")
}
