package core
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"github.com/Cryptochain-VON/accounts"
	"github.com/Cryptochain-VON/accounts/keystore"
	"github.com/Cryptochain-VON/accounts/scwallet"
	"github.com/Cryptochain-VON/accounts/usbwallet"
	"github.com/Cryptochain-VON/common"
	"github.com/Cryptochain-VON/common/hexutil"
	"github.com/Cryptochain-VON/internal/ethapi"
	"github.com/Cryptochain-VON/log"
	"github.com/Cryptochain-VON/rlp"
	"github.com/Cryptochain-VON/signer/storage"
)
const (
	numberOfAccountsToDerive = 10
	ExternalAPIVersion = "6.0.0"
	InternalAPIVersion = "7.0.1"
)
type ExternalAPI interface {
	List(ctx context.Context) ([]common.Address, error)
	New(ctx context.Context) (common.Address, error)
	SignTransaction(ctx context.Context, args SendTxArgs, methodSelector *string) (*ethapi.SignTransactionResult, error)
	SignData(ctx context.Context, contentType string, addr common.MixedcaseAddress, data interface{}) (hexutil.Bytes, error)
	SignTypedData(ctx context.Context, addr common.MixedcaseAddress, data TypedData) (hexutil.Bytes, error)
	EcRecover(ctx context.Context, data hexutil.Bytes, sig hexutil.Bytes) (common.Address, error)
	Version(ctx context.Context) (string, error)
}
type UIClientAPI interface {
	ApproveTx(request *SignTxRequest) (SignTxResponse, error)
	ApproveSignData(request *SignDataRequest) (SignDataResponse, error)
	ApproveListing(request *ListRequest) (ListResponse, error)
	ApproveNewAccount(request *NewAccountRequest) (NewAccountResponse, error)
	ShowError(message string)
	ShowInfo(message string)
	OnApprovedTx(tx ethapi.SignTransactionResult)
	OnSignerStartup(info StartupInfo)
	OnInputRequired(info UserInputRequest) (UserInputResponse, error)
	RegisterUIServer(api *UIServerAPI)
}
type Validator interface {
	ValidateTransaction(selector *string, tx *SendTxArgs) (*ValidationMessages, error)
}
type SignerAPI struct {
	chainID     *big.Int
	am          *accounts.Manager
	UI          UIClientAPI
	validator   Validator
	rejectMode  bool
	credentials storage.Storage
}
type Metadata struct {
	Remote    string `json:"remote"`
	Local     string `json:"local"`
	Scheme    string `json:"scheme"`
	UserAgent string `json:"User-Agent"`
	Origin    string `json:"Origin"`
}
func StartClefAccountManager(ksLocation string, nousb, lightKDF bool, scpath string) *accounts.Manager {
	var (
		backends []accounts.Backend
		n, p     = keystore.StandardScryptN, keystore.StandardScryptP
	)
	if lightKDF {
		n, p = keystore.LightScryptN, keystore.LightScryptP
	}
	if len(ksLocation) > 0 {
		backends = append(backends, keystore.NewKeyStore(ksLocation, n, p))
	}
	if !nousb {
		if ledgerhub, err := usbwallet.NewLedgerHub(); err != nil {
			log.Warn(fmt.Sprintf("Failed to start Ledger hub, disabling: %v", err))
		} else {
			backends = append(backends, ledgerhub)
			log.Debug("Ledger support enabled")
		}
		if trezorhub, err := usbwallet.NewTrezorHubWithHID(); err != nil {
			log.Warn(fmt.Sprintf("Failed to start HID Trezor hub, disabling: %v", err))
		} else {
			backends = append(backends, trezorhub)
			log.Debug("Trezor support enabled via HID")
		}
		if trezorhub, err := usbwallet.NewTrezorHubWithWebUSB(); err != nil {
			log.Warn(fmt.Sprintf("Failed to start WebUSB Trezor hub, disabling: %v", err))
		} else {
			backends = append(backends, trezorhub)
			log.Debug("Trezor support enabled via WebUSB")
		}
	}
	if len(scpath) > 0 {
		fi, err := os.Stat(scpath)
		if err != nil {
			log.Info("Smartcard socket file missing, disabling", "err", err)
		} else {
			if fi.Mode()&os.ModeType != os.ModeSocket {
				log.Error("Invalid smartcard socket file type", "path", scpath, "type", fi.Mode().String())
			} else {
				if schub, err := scwallet.NewHub(scpath, scwallet.Scheme, ksLocation); err != nil {
					log.Warn(fmt.Sprintf("Failed to start smart card hub, disabling: %v", err))
				} else {
					backends = append(backends, schub)
				}
			}
		}
	}
	return accounts.NewManager(&accounts.Config{InsecureUnlockAllowed: false}, backends...)
}
func MetadataFromContext(ctx context.Context) Metadata {
	m := Metadata{"NA", "NA", "NA", "", ""} 
	if v := ctx.Value("remote"); v != nil {
		m.Remote = v.(string)
	}
	if v := ctx.Value("scheme"); v != nil {
		m.Scheme = v.(string)
	}
	if v := ctx.Value("local"); v != nil {
		m.Local = v.(string)
	}
	if v := ctx.Value("Origin"); v != nil {
		m.Origin = v.(string)
	}
	if v := ctx.Value("User-Agent"); v != nil {
		m.UserAgent = v.(string)
	}
	return m
}
func (m Metadata) String() string {
	s, err := json.Marshal(m)
	if err == nil {
		return string(s)
	}
	return err.Error()
}
type (
	SignTxRequest struct {
		Transaction SendTxArgs       `json:"transaction"`
		Callinfo    []ValidationInfo `json:"call_info"`
		Meta        Metadata         `json:"meta"`
	}
	SignTxResponse struct {
		Transaction SendTxArgs `json:"transaction"`
		Approved    bool       `json:"approved"`
	}
	SignDataRequest struct {
		ContentType string                  `json:"content_type"`
		Address     common.MixedcaseAddress `json:"address"`
		Rawdata     []byte                  `json:"raw_data"`
		Messages    []*NameValueType        `json:"messages"`
		Hash        hexutil.Bytes           `json:"hash"`
		Meta        Metadata                `json:"meta"`
	}
	SignDataResponse struct {
		Approved bool `json:"approved"`
	}
	NewAccountRequest struct {
		Meta Metadata `json:"meta"`
	}
	NewAccountResponse struct {
		Approved bool `json:"approved"`
	}
	ListRequest struct {
		Accounts []accounts.Account `json:"accounts"`
		Meta     Metadata           `json:"meta"`
	}
	ListResponse struct {
		Accounts []accounts.Account `json:"accounts"`
	}
	Message struct {
		Text string `json:"text"`
	}
	StartupInfo struct {
		Info map[string]interface{} `json:"info"`
	}
	UserInputRequest struct {
		Title      string `json:"title"`
		Prompt     string `json:"prompt"`
		IsPassword bool   `json:"isPassword"`
	}
	UserInputResponse struct {
		Text string `json:"text"`
	}
)
var ErrRequestDenied = errors.New("request denied")
func NewSignerAPI(am *accounts.Manager, chainID int64, noUSB bool, ui UIClientAPI, validator Validator, advancedMode bool, credentials storage.Storage) *SignerAPI {
	if advancedMode {
		log.Info("Clef is in advanced mode: will warn instead of reject")
	}
	signer := &SignerAPI{big.NewInt(chainID), am, ui, validator, !advancedMode, credentials}
	if !noUSB {
		signer.startUSBListener()
	}
	return signer
}
func (api *SignerAPI) openTrezor(url accounts.URL) {
	resp, err := api.UI.OnInputRequired(UserInputRequest{
		Prompt: "Pin required to open Trezor wallet\n" +
			"Look at the device for number positions\n\n" +
			"7 | 8 | 9\n" +
			"--+---+--\n" +
			"4 | 5 | 6\n" +
			"--+---+--\n" +
			"1 | 2 | 3\n\n",
		IsPassword: true,
		Title:      "Trezor unlock",
	})
	if err != nil {
		log.Warn("failed getting trezor pin", "err", err)
		return
	}
	w, err := api.am.Wallet(url.String())
	if err != nil {
		log.Warn("wallet unavailable", "url", url)
		return
	}
	err = w.Open(resp.Text)
	if err != nil {
		log.Warn("failed to open wallet", "wallet", url, "err", err)
		return
	}
}
func (api *SignerAPI) startUSBListener() {
	events := make(chan accounts.WalletEvent, 16)
	am := api.am
	am.Subscribe(events)
	go func() {
		for _, wallet := range am.Wallets() {
			if err := wallet.Open(""); err != nil {
				log.Warn("Failed to open wallet", "url", wallet.URL(), "err", err)
				if err == usbwallet.ErrTrezorPINNeeded {
					go api.openTrezor(wallet.URL())
				}
			}
		}
		for event := range events {
			switch event.Kind {
			case accounts.WalletArrived:
				if err := event.Wallet.Open(""); err != nil {
					log.Warn("New wallet appeared, failed to open", "url", event.Wallet.URL(), "err", err)
					if err == usbwallet.ErrTrezorPINNeeded {
						go api.openTrezor(event.Wallet.URL())
					}
				}
			case accounts.WalletOpened:
				status, _ := event.Wallet.Status()
				log.Info("New wallet appeared", "url", event.Wallet.URL(), "status", status)
				var nextPath = make(accounts.DerivationPath, len(accounts.DefaultBaseDerivationPath))
				copy(nextPath[:], accounts.DefaultBaseDerivationPath[:])
				for i := 0; i < numberOfAccountsToDerive; i++ {
					acc, err := event.Wallet.Derive(nextPath, true)
					if err != nil {
						log.Warn("account derivation failed", "error", err)
					} else {
						log.Info("derived account", "address", acc.Address)
					}
					nextPath[len(nextPath)-1]++
				}
			case accounts.WalletDropped:
				log.Info("Old wallet dropped", "url", event.Wallet.URL())
				event.Wallet.Close()
			}
		}
	}()
}
func (api *SignerAPI) List(ctx context.Context) ([]common.Address, error) {
	var accs []accounts.Account
	for _, wallet := range api.am.Wallets() {
		accs = append(accs, wallet.Accounts()...)
	}
	result, err := api.UI.ApproveListing(&ListRequest{Accounts: accs, Meta: MetadataFromContext(ctx)})
	if err != nil {
		return nil, err
	}
	if result.Accounts == nil {
		return nil, ErrRequestDenied
	}
	addresses := make([]common.Address, 0)
	for _, acc := range result.Accounts {
		addresses = append(addresses, acc.Address)
	}
	return addresses, nil
}
func (api *SignerAPI) New(ctx context.Context) (common.Address, error) {
	if be := api.am.Backends(keystore.KeyStoreType); len(be) == 0 {
		return common.Address{}, errors.New("password based accounts not supported")
	}
	if resp, err := api.UI.ApproveNewAccount(&NewAccountRequest{MetadataFromContext(ctx)}); err != nil {
		return common.Address{}, err
	} else if !resp.Approved {
		return common.Address{}, ErrRequestDenied
	}
	return api.newAccount()
}
func (api *SignerAPI) newAccount() (common.Address, error) {
	be := api.am.Backends(keystore.KeyStoreType)
	if len(be) == 0 {
		return common.Address{}, errors.New("password based accounts not supported")
	}
	for i := 0; i < 3; i++ {
		resp, err := api.UI.OnInputRequired(UserInputRequest{
			"New account password",
			fmt.Sprintf("Please enter a password for the new account to be created (attempt %d of 3)", i),
			true})
		if err != nil {
			log.Warn("error obtaining password", "attempt", i, "error", err)
			continue
		}
		if pwErr := ValidatePasswordFormat(resp.Text); pwErr != nil {
			api.UI.ShowError(fmt.Sprintf("Account creation attempt #%d failed due to password requirements: %v", (i + 1), pwErr))
		} else {
			acc, err := be[0].(*keystore.KeyStore).NewAccount(resp.Text)
			log.Info("Your new key was generated", "address", acc.Address)
			log.Warn("Please backup your key file!", "path", acc.URL.Path)
			log.Warn("Please remember your password!")
			return acc.Address, err
		}
	}
	return common.Address{}, errors.New("account creation failed")
}
func logDiff(original *SignTxRequest, new *SignTxResponse) bool {
	modified := false
	if f0, f1 := original.Transaction.From, new.Transaction.From; !reflect.DeepEqual(f0, f1) {
		log.Info("Sender-account changed by UI", "was", f0, "is", f1)
		modified = true
	}
	if t0, t1 := original.Transaction.To, new.Transaction.To; !reflect.DeepEqual(t0, t1) {
		log.Info("Recipient-account changed by UI", "was", t0, "is", t1)
		modified = true
	}
	if g0, g1 := original.Transaction.Gas, new.Transaction.Gas; g0 != g1 {
		modified = true
		log.Info("Gas changed by UI", "was", g0, "is", g1)
	}
	if g0, g1 := big.Int(original.Transaction.GasPrice), big.Int(new.Transaction.GasPrice); g0.Cmp(&g1) != 0 {
		modified = true
		log.Info("GasPrice changed by UI", "was", g0, "is", g1)
	}
	if v0, v1 := big.Int(original.Transaction.Value), big.Int(new.Transaction.Value); v0.Cmp(&v1) != 0 {
		modified = true
		log.Info("Value changed by UI", "was", v0, "is", v1)
	}
	if d0, d1 := original.Transaction.Data, new.Transaction.Data; d0 != d1 {
		d0s := ""
		d1s := ""
		if d0 != nil {
			d0s = hexutil.Encode(*d0)
		}
		if d1 != nil {
			d1s = hexutil.Encode(*d1)
		}
		if d1s != d0s {
			modified = true
			log.Info("Data changed by UI", "was", d0s, "is", d1s)
		}
	}
	if n0, n1 := original.Transaction.Nonce, new.Transaction.Nonce; n0 != n1 {
		modified = true
		log.Info("Nonce changed by UI", "was", n0, "is", n1)
	}
	return modified
}
func (api *SignerAPI) lookupPassword(address common.Address) (string, error) {
	return api.credentials.Get(address.Hex())
}
func (api *SignerAPI) lookupOrQueryPassword(address common.Address, title, prompt string) (string, error) {
	if pw, err := api.lookupPassword(address); err == nil {
		return pw, nil
	}
	pwResp, err := api.UI.OnInputRequired(UserInputRequest{title, prompt, true})
	if err != nil {
		log.Warn("error obtaining password", "error", err)
		return "", errors.New("internal error")
	}
	return pwResp.Text, nil
}
func (api *SignerAPI) SignTransaction(ctx context.Context, args SendTxArgs, methodSelector *string) (*ethapi.SignTransactionResult, error) {
	var (
		err    error
		result SignTxResponse
	)
	msgs, err := api.validator.ValidateTransaction(methodSelector, &args)
	if err != nil {
		return nil, err
	}
	if api.rejectMode {
		if err := msgs.getWarnings(); err != nil {
			return nil, err
		}
	}
	req := SignTxRequest{
		Transaction: args,
		Meta:        MetadataFromContext(ctx),
		Callinfo:    msgs.Messages,
	}
	result, err = api.UI.ApproveTx(&req)
	if err != nil {
		return nil, err
	}
	if !result.Approved {
		return nil, ErrRequestDenied
	}
	logDiff(&req, &result)
	var (
		acc    accounts.Account
		wallet accounts.Wallet
	)
	acc = accounts.Account{Address: result.Transaction.From.Address()}
	wallet, err = api.am.Find(acc)
	if err != nil {
		return nil, err
	}
	var unsignedTx = result.Transaction.toTransaction()
	pw, err := api.lookupOrQueryPassword(acc.Address, "Account password",
		fmt.Sprintf("Please enter the password for account %s", acc.Address.String()))
	if err != nil {
		return nil, err
	}
	signedTx, err := wallet.SignTxWithPassphrase(acc, pw, unsignedTx, api.chainID)
	if err != nil {
		api.UI.ShowError(err.Error())
		return nil, err
	}
	rlpdata, err := rlp.EncodeToBytes(signedTx)
	if err != nil {
		return nil, err
	}
	response := ethapi.SignTransactionResult{Raw: rlpdata, Tx: signedTx}
	api.UI.OnApprovedTx(response)
	return &response, nil
}
func (api *SignerAPI) Version(ctx context.Context) (string, error) {
	return ExternalAPIVersion, nil
}
