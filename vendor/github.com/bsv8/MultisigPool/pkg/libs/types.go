package libs

// UTXO represents an unspent transaction output
type UTXO struct {
	TxID  string `json:"txid"`
	Vout  uint32 `json:"vout"`
	Value uint64 `json:"satoshis"`
}
