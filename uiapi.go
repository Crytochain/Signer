package core
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"github.com/Cryptochain-VON/accounts"
	"github.com/Cryptochain-VON/accounts/keystore"
	"github.com/Cryptochain-VON/common"
	"github.com/Cryptochain-VON/common/math"
	"github.com/Cryptochain-VON/crypto"
)
type UIServerAPI struct {
	extApi *SignerAPI
	am     *accounts.Manager
}
func NewUIServerAPI(extapi *SignerAPI) *UIServerAPI {
	return &UIServerAPI{extapi, extapi.am}
}
func (s *UIServerAPI) ListAccounts(ctx context.Context) ([]accounts.Account, error) {
	var accs []accounts.Account
	for _, wallet := range s.am.Wallets() {
		accs = append(accs, wallet.Accounts()...)
	}
	return accs, nil
}
type rawWallet struct {
	URL      string             `json:"url"`
	Status   string             `json:"status"`
	Failure  string             `json:"failure,omitempty"`
	Accounts []accounts.Account `json:"accounts,omitempty"`
}
func (s *UIServerAPI) ListWallets() []rawWallet {
	wallets := make([]rawWallet, 0) 
	for _, wallet := range s.am.Wallets() {
		status, failure := wallet.Status()
		raw := rawWallet{
			URL:      wallet.URL().String(),
			Status:   status,
			Accounts: wallet.Accounts(),
		}
		if failure != nil {
			raw.Failure = failure.Error()
		}
		wallets = append(wallets, raw)
	}
	return wallets
}
func (s *UIServerAPI) DeriveAccount(url string, path string, pin *bool) (accounts.Account, error) {
	wallet, err := s.am.Wallet(url)
	if err != nil {
		return accounts.Account{}, err
	}
	derivPath, err := accounts.ParseDerivationPath(path)
	if err != nil {
		return accounts.Account{}, err
	}
	if pin == nil {
		pin = new(bool)
	}
	return wallet.Derive(derivPath, *pin)
}
func fetchKeystore(am *accounts.Manager) *keystore.KeyStore {
	return am.Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)
}
func (s *UIServerAPI) ImportRawKey(privkey string, password string) (accounts.Account, error) {
	key, err := crypto.HexToECDSA(privkey)
	if err != nil {
		return accounts.Account{}, err
	}
	if err := ValidatePasswordFormat(password); err != nil {
		return accounts.Account{}, fmt.Errorf("password requirements not met: %v", err)
	}
	return fetchKeystore(s.am).ImportECDSA(key, password)
}
func (s *UIServerAPI) OpenWallet(url string, passphrase *string) error {
	wallet, err := s.am.Wallet(url)
	if err != nil {
		return err
	}
	pass := ""
	if passphrase != nil {
		pass = *passphrase
	}
	return wallet.Open(pass)
}
func (s *UIServerAPI) ChainId() math.HexOrDecimal64 {
	return (math.HexOrDecimal64)(s.extApi.chainID.Uint64())
}
func (s *UIServerAPI) SetChainId(id math.HexOrDecimal64) math.HexOrDecimal64 {
	s.extApi.chainID = new(big.Int).SetUint64(uint64(id))
	return s.ChainId()
}
func (s *UIServerAPI) Export(ctx context.Context, addr common.Address) (json.RawMessage, error) {
	wallet, err := s.am.Find(accounts.Account{Address: addr})
	if err != nil {
		return nil, err
	}
	if wallet.URL().Scheme != keystore.KeyStoreScheme {
		return nil, fmt.Errorf("account is not a keystore-account")
	}
	return ioutil.ReadFile(wallet.URL().Path)
}
func (api *UIServerAPI) Import(ctx context.Context, keyJSON json.RawMessage, oldPassphrase, newPassphrase string) (accounts.Account, error) {
	be := api.am.Backends(keystore.KeyStoreType)
	if len(be) == 0 {
		return accounts.Account{}, errors.New("password based accounts not supported")
	}
	if err := ValidatePasswordFormat(newPassphrase); err != nil {
		return accounts.Account{}, fmt.Errorf("password requirements not met: %v", err)
	}
	return be[0].(*keystore.KeyStore).Import(keyJSON, oldPassphrase, newPassphrase)
}
func (api *UIServerAPI) New(ctx context.Context) (common.Address, error) {
	return api.extApi.newAccount()
}
