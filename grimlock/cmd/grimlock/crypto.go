// Crypto utilities for Grimlock
//
// HKDF key derivation and kTLS structures.
// Updated to match verified Grimlock production implementation.

package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/crypto/hkdf"
)

// Kernel kTLS constants (numeric values for cross-compilation)
const (
	solTCP             = 6   // SOL_TCP
	solTLS             = 282 // SOL_TLS
	tlsTX              = 1   // TLS_TX
	tlsRX              = 2   // TLS_RX
	tcpULP             = 31  // TCP_ULP
	ulpName            = "tls"
	tlsVersionTLS13    = 0x0304
	tlsCipherAESGCM128 = 51
)

// tlsCryptoInfoAESGCM128 matches kernel struct for kTLS.
// Total size must be exactly 40 bytes.
type tlsCryptoInfoAESGCM128 struct {
	Version    uint16
	CipherType uint16
	IV         [8]byte
	Key        [16]byte
	Salt       [4]byte
	RecSeq     [8]byte
}

// hkdfExpandLabel implements TLS 1.3 HKDF-Expand-Label (RFC 8446 Section 7.1)
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) ([]byte, error) {
	fullLabel := "tls13 " + label
	hkdfLabel := make([]byte, 2+1+len(fullLabel)+1+len(context))
	hkdfLabel[0] = byte(length >> 8)
	hkdfLabel[1] = byte(length)
	hkdfLabel[2] = byte(len(fullLabel))
	copy(hkdfLabel[3:], fullLabel)
	hkdfLabel[3+len(fullLabel)] = byte(len(context))
	copy(hkdfLabel[4+len(fullLabel):], context)

	reader := hkdf.Expand(sha256.New, secret, hkdfLabel)
	result := make([]byte, length)
	if _, err := io.ReadFull(reader, result); err != nil {
		return nil, err
	}
	return result, nil
}

// deriveTrafficKeys derives key and IV from a traffic secret
func deriveTrafficKeys(trafficSecret []byte) (key []byte, iv []byte, err error) {
	key, err = hkdfExpandLabel(trafficSecret, "key", nil, 16)
	if err != nil {
		return nil, nil, fmt.Errorf("derive key: %w", err)
	}

	iv, err = hkdfExpandLabel(trafficSecret, "iv", nil, 12)
	if err != nil {
		return nil, nil, fmt.Errorf("derive iv: %w", err)
	}

	return key, iv, nil
}

// getTCPConn extracts the underlying TCP connection from a tls.Conn
// using the stable NetConn() API (Go 1.18+).
func getTCPConn(conn *tls.Conn) (*net.TCPConn, error) {
	if conn == nil {
		return nil, fmt.Errorf("tls.Conn is nil")
	}
	netConn := conn.NetConn()
	tcpConn, ok := netConn.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("underlying conn is %T, not *net.TCPConn", netConn)
	}
	return tcpConn, nil
}

// enableKTLS configures kernel TLS on a tls.Conn via the underlying TCP socket.
func enableKTLS(conn *tls.Conn, isClient bool, clientSecret, serverSecret []byte) error {
	tcpConn, err := getTCPConn(conn)
	if err != nil {
		return fmt.Errorf("get TCP conn: %w", err)
	}
	return enableKTLSOnTCP(tcpConn, isClient, clientSecret, serverSecret)
}

// enableKTLSOnTCP configures kernel TLS directly on a *net.TCPConn.
// Use this when you have the raw TCP socket (e.g., from net.Listen + Accept).
func enableKTLSOnTCP(tcpConn *net.TCPConn, isClient bool, clientSecret, serverSecret []byte) error {
	clientKey, clientIV, err := deriveTrafficKeys(clientSecret)
	if err != nil {
		return fmt.Errorf("derive client keys: %w", err)
	}
	serverKey, serverIV, err := deriveTrafficKeys(serverSecret)
	if err != nil {
		return fmt.Errorf("derive server keys: %w", err)
	}

	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("get syscall conn: %w", err)
	}

	var txKey, txIV, rxKey, rxIV []byte
	if isClient {
		txKey, txIV = clientKey, clientIV
		rxKey, rxIV = serverKey, serverIV
	} else {
		txKey, txIV = serverKey, serverIV
		rxKey, rxIV = clientKey, clientIV
	}

	var sockErr error
	err = rawConn.Control(func(fd uintptr) {
		if err := syscall.SetsockoptString(int(fd), solTCP, tcpULP, ulpName); err != nil {
			sockErr = fmt.Errorf("set TCP_ULP: %w", err)
			return
		}

		txInfo := tlsCryptoInfoAESGCM128{
			Version:    tlsVersionTLS13,
			CipherType: tlsCipherAESGCM128,
		}
		copy(txInfo.Key[:], txKey)
		copy(txInfo.Salt[:], txIV[:4])
		copy(txInfo.IV[:], txIV[4:12])

		txInfoBytes := (*[40]byte)(unsafe.Pointer(&txInfo))[:]
		_, _, errno := syscall.Syscall6(
			syscall.SYS_SETSOCKOPT,
			fd, uintptr(solTLS), uintptr(tlsTX),
			uintptr(unsafe.Pointer(&txInfoBytes[0])),
			uintptr(len(txInfoBytes)), 0,
		)
		if errno != 0 {
			sockErr = fmt.Errorf("set TLS_TX: %w", errno)
			return
		}

		rxInfo := tlsCryptoInfoAESGCM128{
			Version:    tlsVersionTLS13,
			CipherType: tlsCipherAESGCM128,
		}
		copy(rxInfo.Key[:], rxKey)
		copy(rxInfo.Salt[:], rxIV[:4])
		copy(rxInfo.IV[:], rxIV[4:12])

		rxInfoBytes := (*[40]byte)(unsafe.Pointer(&rxInfo))[:]
		_, _, errno = syscall.Syscall6(
			syscall.SYS_SETSOCKOPT,
			fd, uintptr(solTLS), uintptr(tlsRX),
			uintptr(unsafe.Pointer(&rxInfoBytes[0])),
			uintptr(len(rxInfoBytes)), 0,
		)
		if errno != 0 {
			sockErr = fmt.Errorf("set TLS_RX: %w", errno)
			return
		}
	})
	if err != nil {
		return fmt.Errorf("control: %w", err)
	}
	return sockErr
}

// keyLogWriter captures TLS 1.3 traffic secrets for kTLS setup.
type keyLogWriter struct {
	mu   sync.Mutex
	keys map[string][]byte
}

func newKeyLogWriter() *keyLogWriter {
	return &keyLogWriter{keys: make(map[string][]byte)}
}

func (w *keyLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	line := string(p)
	parts := strings.Fields(line)
	if len(parts) >= 3 {
		label := parts[0]
		secretBytes, err := hex.DecodeString(parts[2])
		if err == nil && len(secretBytes) > 0 {
			w.keys[label] = secretBytes
		}
	}
	return len(p), nil
}

func (w *keyLogWriter) GetKeys() (clientSecret, serverSecret []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.keys["CLIENT_TRAFFIC_SECRET_0"], w.keys["SERVER_TRAFFIC_SECRET_0"]
}

func (w *keyLogWriter) Reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	for k, v := range w.keys {
		for i := range v {
			v[i] = 0
		}
		delete(w.keys, k)
	}
}
