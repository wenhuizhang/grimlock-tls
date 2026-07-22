// Tamper-evident payment receipt log (F4).
//
// Every payment decision Grimlock makes is recorded as a Receipt and appended to
// a hash-chained, append-only JSONL log: each entry commits to the hash of the
// previous one, so any later edit/removal breaks the chain and is detectable by
// an auditor. The chain head is recovered from the existing file on restart, and
// writes are flushed to disk, so the chain is durable and continuous.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Receipt is one entry in the audit log.
type Receipt struct {
	Time        time.Time `json:"time"`
	Method      string    `json:"method"`
	Network     string    `json:"network"`
	PayTo       string    `json:"payTo"`
	Value       string    `json:"value"`
	Allowed     bool      `json:"allowed"`
	Reason      string    `json:"reason"`
	BindingHash string    `json:"bindingHash"`        // hex SHA-256 of payment terms
	QuoteB64    string    `json:"quoteB64,omitempty"` // base64 TDX quote bound to the payment
	SettleTx    string    `json:"settleTx,omitempty"` // on-chain tx hash (from X-PAYMENT-RESPONSE)
	SettleOK    bool      `json:"settleOK,omitempty"` //
	PrevHash    string    `json:"prevHash"`           // chain link
	Hash        string    `json:"hash"`               // SHA-256 over this entry (excl. Hash)
}

// hashHex computes the entry hash over all fields except Hash itself.
func (r *Receipt) hashHex() string {
	c := *r
	c.Hash = ""
	b, _ := json.Marshal(&c)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ReceiptLog is an append-only, hash-chained writer of receipts (JSONL).
type ReceiptLog struct {
	mu   sync.Mutex
	w    io.Writer
	f    *os.File // non-nil when backed by a file (for fsync)
	prev string
}

// NewReceiptLog writes receipts to w (e.g. os.Stderr or an in-memory buffer).
// The chain starts from an empty head; use OpenReceiptLogFile for durable,
// restart-continuous logs.
func NewReceiptLog(w io.Writer) *ReceiptLog {
	return &ReceiptLog{w: w}
}

// OpenReceiptLogFile opens (creating) an append-only receipt log at path,
// recovering the chain head from the last existing entry so a restart continues
// the same chain rather than starting a fresh one.
func OpenReceiptLogFile(path string) (*ReceiptLog, error) {
	prev, err := lastReceiptHash(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &ReceiptLog{w: f, f: f, prev: prev}, nil
}

// lastReceiptHash returns the Hash of the final entry in an existing log, or ""
// if the file does not exist / is empty.
func lastReceiptHash(path string) (string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return "", nil
	}
	lines := bytes.Split(b, []byte("\n"))
	var r Receipt
	if err := json.Unmarshal(lines[len(lines)-1], &r); err != nil {
		return "", fmt.Errorf("corrupt receipt log %s: %w", path, err)
	}
	return r.Hash, nil
}

// Append links the receipt to the chain, writes it, and (for a file) fsyncs. The
// chain head only advances on a successful write, so a failed write drops the
// receipt without corrupting the chain.
func (l *ReceiptLog) Append(r *Receipt) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	r.PrevHash = l.prev
	r.Hash = r.hashHex()
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	if _, err := l.w.Write(line); err != nil {
		return err
	}
	if l.f != nil {
		if err := l.f.Sync(); err != nil {
			return err
		}
	}
	l.prev = r.Hash
	return nil
}

// VerifyChain checks that a slice of receipts forms an unbroken hash chain
// (genesis prev == ""). Returns the index of the first broken link, or -1 if OK.
func VerifyChain(entries []*Receipt) int {
	prev := ""
	for i, r := range entries {
		if r.PrevHash != prev {
			return i
		}
		if r.Hash != r.hashHex() {
			return i
		}
		prev = r.Hash
	}
	return -1
}
