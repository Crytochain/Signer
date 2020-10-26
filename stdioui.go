package core
import (
	"context"
	"github.com/Cryptochain-VON/internal/ethapi"
	"github.com/Cryptochain-VON/log"
	"github.com/Cryptochain-VON/rpc"
)
type StdIOUI struct {
	client rpc.Client
}
func NewStdIOUI() *StdIOUI {
	client, err := rpc.DialContext(context.Background(), "stdio:
	if err != nil {
		log.Crit("Could not create stdio client", "err", err)
	}
	ui := &StdIOUI{client: *client}
	return ui
}
func (ui *StdIOUI) RegisterUIServer(api *UIServerAPI) {
	ui.client.RegisterName("clef", api)
}
func (ui *StdIOUI) dispatch(serviceMethod string, args interface{}, reply interface{}) error {
	err := ui.client.Call(&reply, serviceMethod, args)
	if err != nil {
		log.Info("Error", "exc", err.Error())
	}
	return err
}
func (ui *StdIOUI) notify(serviceMethod string, args interface{}) error {
	ctx := context.Background()
	err := ui.client.Notify(ctx, serviceMethod, args)
	if err != nil {
		log.Info("Error", "exc", err.Error())
	}
	return err
}
func (ui *StdIOUI) ApproveTx(request *SignTxRequest) (SignTxResponse, error) {
	var result SignTxResponse
	err := ui.dispatch("ui_approveTx", request, &result)
	return result, err
}
func (ui *StdIOUI) ApproveSignData(request *SignDataRequest) (SignDataResponse, error) {
	var result SignDataResponse
	err := ui.dispatch("ui_approveSignData", request, &result)
	return result, err
}
func (ui *StdIOUI) ApproveListing(request *ListRequest) (ListResponse, error) {
	var result ListResponse
	err := ui.dispatch("ui_approveListing", request, &result)
	return result, err
}
func (ui *StdIOUI) ApproveNewAccount(request *NewAccountRequest) (NewAccountResponse, error) {
	var result NewAccountResponse
	err := ui.dispatch("ui_approveNewAccount", request, &result)
	return result, err
}
func (ui *StdIOUI) ShowError(message string) {
	err := ui.notify("ui_showError", &Message{message})
	if err != nil {
		log.Info("Error calling 'ui_showError'", "exc", err.Error(), "msg", message)
	}
}
func (ui *StdIOUI) ShowInfo(message string) {
	err := ui.notify("ui_showInfo", Message{message})
	if err != nil {
		log.Info("Error calling 'ui_showInfo'", "exc", err.Error(), "msg", message)
	}
}
func (ui *StdIOUI) OnApprovedTx(tx ethapi.SignTransactionResult) {
	err := ui.notify("ui_onApprovedTx", tx)
	if err != nil {
		log.Info("Error calling 'ui_onApprovedTx'", "exc", err.Error(), "tx", tx)
	}
}
func (ui *StdIOUI) OnSignerStartup(info StartupInfo) {
	err := ui.notify("ui_onSignerStartup", info)
	if err != nil {
		log.Info("Error calling 'ui_onSignerStartup'", "exc", err.Error(), "info", info)
	}
}
func (ui *StdIOUI) OnInputRequired(info UserInputRequest) (UserInputResponse, error) {
	var result UserInputResponse
	err := ui.dispatch("ui_onInputRequired", info, &result)
	if err != nil {
		log.Info("Error calling 'ui_onInputRequired'", "exc", err.Error(), "info", info)
	}
	return result, err
}
