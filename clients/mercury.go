package clients

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/renproject/libzec-go/errors"
	"github.com/renproject/mercury/btc"
)

type mercuryClient struct {
	URL    string
	Params *chaincfg.Params
}

func NewMercuryClientCore(network string) (ClientCore, error) {
	network = strings.ToLower(network)
	switch network {
	case "mainnet":
		return &mercuryClient{
			URL:    "",
			Params: &chaincfg.MainNetParams,
		}, nil
	case "testnet", "testnet3", "":
		return &mercuryClient{
			URL:    "http://127.0.0.1:8123/btc-testnet3",
			Params: &chaincfg.TestNet3Params,
		}, nil
	default:
		return nil, errors.NewErrUnsupportedNetwork(network)
	}
}

func (client *mercuryClient) NetworkParams() *chaincfg.Params {
	return client.Params
}

func (client *mercuryClient) GetUTXOs(ctx context.Context, address string, limit, confitmations int64) ([]UTXO, error) {
	utxos := []UTXO{}
	resp, err := http.Get(fmt.Sprintf("%s/utxo/%s?limit=%d&confirmations=%d", client.URL, address, limit, confitmations))
	if err != nil || resp.StatusCode != http.StatusOK {
		if err != nil {
			return utxos, err
		}
		respErr := MercuryError{}
		if err := json.NewDecoder(resp.Body).Decode(&respErr); err != nil {
			return utxos, err
		}
		return utxos, fmt.Errorf("request failed with (%d): %s", resp.StatusCode, respErr.Error)
	}

	if err := json.NewDecoder(resp.Body).Decode(&utxos); err != nil {
		return utxos, err
	}
	return utxos, nil
}

func (client *mercuryClient) Confirmations(ctx context.Context, txHash string) (int64, error) {
	var conf btc.GetConfirmationsResponse
	resp, err := http.Get(fmt.Sprintf("%s/confirmations/%s", client.URL, txHash))
	if err != nil || resp.StatusCode != http.StatusOK {
		if err != nil {
			return 0, err
		}
		respErr := MercuryError{}
		if err := json.NewDecoder(resp.Body).Decode(&respErr); err != nil {
			return 0, err
		}
		return 0, fmt.Errorf("request failed with (%d): %s", resp.StatusCode, respErr.Error)
	}
	if err := json.NewDecoder(resp.Body).Decode(&conf); err != nil {
		return 0, err
	}
	return int64(conf), nil
}

func (client *mercuryClient) ScriptSpent(ctx context.Context, script, spender string) (bool, string, error) {
	var scriptResp btc.GetScriptResponse
	resp, err := http.Get(fmt.Sprintf("%s/script/spent/%s?spender=%s", client.URL, script, spender))
	if err != nil || resp.StatusCode != http.StatusOK {
		if err != nil {
			return false, "", err
		}
		respErr := MercuryError{}
		if err := json.NewDecoder(resp.Body).Decode(&respErr); err != nil {
			return false, "", err
		}
		return false, "", fmt.Errorf("request failed with (%d): %s", resp.StatusCode, respErr.Error)
	}
	if err := json.NewDecoder(resp.Body).Decode(&scriptResp); err != nil {
		return false, "", err
	}
	return scriptResp.Status, scriptResp.Script, nil
}

func (client *mercuryClient) ScriptFunded(ctx context.Context, address string, value int64) (bool, int64, error) {
	fmt.Println(fmt.Sprintf("%s/script/funded/%s?value=%d", client.URL, address, value))

	var scriptResp btc.GetScriptResponse
	resp, err := http.Get(fmt.Sprintf("%s/script/funded/%s?value=%d", client.URL, address, value))
	if err != nil || resp.StatusCode != http.StatusOK {
		if err != nil {
			return false, 0, err
		}
		respErr := MercuryError{}
		if err := json.NewDecoder(resp.Body).Decode(&respErr); err != nil {
			return false, 0, err
		}
		return false, 0, fmt.Errorf("request failed with (%d): %s", resp.StatusCode, respErr.Error)
	}
	if err := json.NewDecoder(resp.Body).Decode(&scriptResp); err != nil {
		return false, 0, err
	}
	return scriptResp.Status, scriptResp.Value, nil
}

func (client *mercuryClient) ScriptRedeemed(ctx context.Context, address string, value int64) (bool, int64, error) {
	var scriptResp btc.GetScriptResponse
	resp, err := http.Get(fmt.Sprintf("%s/script/redeemed/%s?value=%d", client.URL, address, value))
	if err != nil || resp.StatusCode != http.StatusOK {
		if err != nil {
			return false, 0, err
		}
		respErr := MercuryError{}
		if err := json.NewDecoder(resp.Body).Decode(&respErr); err != nil {
			return false, 0, err
		}
		return false, 0, fmt.Errorf("request failed with (%d): %s", resp.StatusCode, respErr.Error)
	}
	if err := json.NewDecoder(resp.Body).Decode(&scriptResp); err != nil {
		return false, 0, err
	}
	return scriptResp.Status, scriptResp.Value, nil
}

func (client *mercuryClient) PublishTransaction(ctx context.Context, stx []byte) error {
	req := btc.PostTransactionRequest{
		SignedTransaction: hex.EncodeToString(stx),
	}

	fmt.Println(hex.EncodeToString(stx))

	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(&req); err != nil {
		return err
	}

	if resp, err := http.Post(fmt.Sprintf("%s/tx", client.URL), "application/json", buf); err != nil || resp.StatusCode != http.StatusCreated {
		if err != nil {
			return err
		}
		respErr := MercuryError{}
		if err := json.NewDecoder(resp.Body).Decode(&respErr); err != nil {
			return err
		}
		return fmt.Errorf("request failed with (%d): %s", resp.StatusCode, respErr.Error)
	}
	return nil
}

type MercuryError struct {
	Error string `json:"error"`
}
