package fourbyte
import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"github.com/Cryptochain-VON/common"
	"github.com/Cryptochain-VON/signer/core"
)
func (db *Database) ValidateTransaction(selector *string, tx *core.SendTxArgs) (*core.ValidationMessages, error) {
	messages := new(core.ValidationMessages)
	if tx.Data != nil && tx.Input != nil && !bytes.Equal(*tx.Data, *tx.Input) {
		return nil, errors.New(`ambiguous request: both "data" and "input" are set and are not identical`)
	}
	var data []byte
	if tx.Input != nil {
		tx.Data = tx.Input
		tx.Input = nil
	}
	if tx.Data != nil {
		data = *tx.Data
	}
	if tx.To == nil {
		if len(data) == 0 {
			if tx.Value.ToInt().Cmp(big.NewInt(0)) > 0 {
				return nil, errors.New("transaction will create a contract with value but empty code")
			}
			messages.Crit("Transaction will create a contract with empty code")
		} else if len(data) < 40 { 
			messages.Warn(fmt.Sprintf("Transaction will create a contract, but the payload is suspiciously small (%d bytes)", len(data)))
		}
		if selector != nil {
			messages.Warn("Transaction will create a contract, but method selector supplied, indicating an intent to call a method")
		}
		return messages, nil
	}
	if !tx.To.ValidChecksum() {
		messages.Warn("Invalid checksum on recipient address")
	}
	if bytes.Equal(tx.To.Address().Bytes(), common.Address{}.Bytes()) {
		messages.Crit("Transaction recipient is the zero address")
	}
	db.ValidateCallData(selector, data, messages)
	return messages, nil
}
func (db *Database) ValidateCallData(selector *string, data []byte, messages *core.ValidationMessages) {
	if len(data) == 0 {
		return
	}
	if len(data) < 4 {
		messages.Warn("Transaction data is not valid ABI (missing the 4 byte call prefix)")
		return
	}
	if n := len(data) - 4; n%32 != 0 {
		messages.Warn(fmt.Sprintf("Transaction data is not valid ABI (length should be a multiple of 32 (was %d))", n))
	}
	if selector != nil {
		if info, err := verifySelector(*selector, data); err != nil {
			messages.Warn(fmt.Sprintf("Transaction contains data, but provided ABI signature could not be matched: %v", err))
		} else {
			messages.Info(fmt.Sprintf("Transaction invokes the following method: %q", info.String()))
			db.AddSelector(*selector, data[:4])
		}
		return
	}
	embedded, err := db.Selector(data[:4])
	if err != nil {
		messages.Warn(fmt.Sprintf("Transaction contains data, but the ABI signature could not be found: %v", err))
		return
	}
	if info, err := verifySelector(embedded, data); err != nil {
		messages.Warn(fmt.Sprintf("Transaction contains data, but provided ABI signature could not be verified: %v", err))
	} else {
		messages.Info(fmt.Sprintf("Transaction invokes the following method: %q", info.String()))
	}
}
