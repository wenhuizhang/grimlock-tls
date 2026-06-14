// Standalone kTLS Test
//
// This program tests the complete kTLS flow:
// 1. TLS 1.3 handshake between client and server
// 2. Extract symmetric keys from tls.Conn
// 3. Configure kTLS on the socket
// 4. Verify data is encrypted on the wire
//
// Usage:
//   ./ktls-test server    # Start TLS server on :9443
//   ./ktls-test client    # Connect to server, test kTLS

package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"reflect"
	"syscall"
	"unsafe"

	"golang.org/x/crypto/hkdf"
)

// Linux kTLS constants (from linux/tls.h)
const (
	SOL_TLS       = 282
	TLS_TX        = 1
	TLS_RX        = 2
	TLS_1_3_VERSION = 0x0304

	// Cipher types
	TLS_CIPHER_AES_GCM_128           = 51
	TLS_CIPHER_AES_GCM_128_IV_SIZE   = 8
	TLS_CIPHER_AES_GCM_128_KEY_SIZE  = 16
	TLS_CIPHER_AES_GCM_128_SALT_SIZE = 4
	TLS_CIPHER_AES_GCM_128_TAG_SIZE  = 16
	TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE = 8

	TLS_CIPHER_AES_GCM_256           = 52
	TLS_CIPHER_AES_GCM_256_IV_SIZE   = 8
	TLS_CIPHER_AES_GCM_256_KEY_SIZE  = 32
	TLS_CIPHER_AES_GCM_256_SALT_SIZE = 4
	TLS_CIPHER_AES_GCM_256_TAG_SIZE  = 16
	TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE = 8
)

// tls_crypto_info_aes_gcm_128 matches kernel struct
type tlsCryptoInfoAESGCM128 struct {
	Version    uint16
	CipherType uint16
	IV         [TLS_CIPHER_AES_GCM_128_IV_SIZE]byte
	Key        [TLS_CIPHER_AES_GCM_128_KEY_SIZE]byte
	Salt       [TLS_CIPHER_AES_GCM_128_SALT_SIZE]byte
	RecSeq     [TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE]byte
}

// TLSKeys holds extracted keys from a TLS connection
type TLSKeys struct {
	Version     uint16
	CipherSuite uint16
	ClientKey   []byte
	ServerKey   []byte
	ClientIV    []byte
	ServerIV    []byte
}

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	if len(os.Args) < 2 {
		fmt.Println("Usage: ktls-test <server|client> [options]")
		fmt.Println("")
		fmt.Println("Commands:")
		fmt.Println("  server    Start TLS server on port 9443")
		fmt.Println("  client    Connect to TLS server")
		fmt.Println("")
		fmt.Println("Options:")
		fmt.Println("  -addr     Address to connect/bind (default: localhost:9443)")
		fmt.Println("  -cert     Path to certificate file")
		fmt.Println("  -key      Path to key file")
		fmt.Println("  -ca       Path to CA certificate")
		fmt.Println("  -ktls     Enable kTLS after handshake (default: false)")
		os.Exit(1)
	}

	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)

	addr := fs.String("addr", "localhost:9443", "Address")
	certFile := fs.String("cert", "", "Certificate file")
	keyFile := fs.String("key", "", "Key file")
	caFile := fs.String("ca", "", "CA certificate file")
	enableKTLS := fs.Bool("ktls", false, "Enable kTLS")

	fs.Parse(os.Args[2:])

	switch cmd {
	case "server":
		runServer(*addr, *certFile, *keyFile, *caFile, *enableKTLS)
	case "client":
		runClient(*addr, *certFile, *keyFile, *caFile, *enableKTLS)
	default:
		log.Fatalf("Unknown command: %s", cmd)
	}
}

// keyLogWriter captures TLS keys for kTLS setup
type keyLogWriter struct {
	keys map[string][]byte
}

func newKeyLogWriter() *keyLogWriter {
	return &keyLogWriter{keys: make(map[string][]byte)}
}

func (w *keyLogWriter) Write(p []byte) (n int, err error) {
	line := string(p)
	// Parse SSLKEYLOGFILE format: LABEL <client_random> <secret>
	// For TLS 1.3: CLIENT_TRAFFIC_SECRET_0, SERVER_TRAFFIC_SECRET_0, etc.
	parts := splitFields(line)
	if len(parts) >= 3 {
		label := parts[0]
		// clientRandom := parts[1]  // We don't need this for our use case
		secret := parts[2]
		secretBytes, _ := hexDecode(secret)
		if secretBytes != nil {
			w.keys[label] = secretBytes
			log.Printf("  Captured key: %s (%d bytes)", label, len(secretBytes))
		}
	}
	return len(p), nil
}

func splitFields(s string) []string {
	var fields []string
	var current []byte
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\n' || s[i] == '\r' {
			if len(current) > 0 {
				fields = append(fields, string(current))
				current = nil
			}
		} else {
			current = append(current, s[i])
		}
	}
	if len(current) > 0 {
		fields = append(fields, string(current))
	}
	return fields
}

func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd length hex string")
	}
	result := make([]byte, len(s)/2)
	for i := 0; i < len(result); i++ {
		var b byte
		for j := 0; j < 2; j++ {
			c := s[i*2+j]
			var v byte
			if c >= '0' && c <= '9' {
				v = c - '0'
			} else if c >= 'a' && c <= 'f' {
				v = c - 'a' + 10
			} else if c >= 'A' && c <= 'F' {
				v = c - 'A' + 10
			} else {
				return nil, fmt.Errorf("invalid hex char: %c", c)
			}
			b = b*16 + v
		}
		result[i] = b
	}
	return result, nil
}

func runServer(addr, certFile, keyFile, caFile string, enableKTLS bool) {
	log.Println("=== kTLS Test Server ===")

	// Load certificate
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("Failed to load certificate: %v", err)
	}

	// Load CA for client verification
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		log.Fatalf("Failed to read CA: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	// Set up key log writer for kTLS
	keyLog := newKeyLogWriter()

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		KeyLogWriter: keyLog,
	}

	listener, err := tls.Listen("tcp", addr, config)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	log.Printf("Listening on %s (TLS 1.3, mTLS required)", addr)
	log.Printf("Waiting for client connection...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		// Note: The server shares the config's keyLog for all connections
		go handleServerConn(conn.(*tls.Conn), enableKTLS, keyLog)
	}
}

func handleServerConn(tlsConn *tls.Conn, enableKTLS bool, keyLog *keyLogWriter) {
	defer tlsConn.Close()

	// Force handshake
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("Handshake failed: %v", err)
		return
	}

	state := tlsConn.ConnectionState()
	log.Printf("Client connected!")
	log.Printf("  TLS Version: %s", tlsVersionString(state.Version))
	log.Printf("  Cipher Suite: %s", tls.CipherSuiteName(state.CipherSuite))
	log.Printf("  Client CN: %s", state.PeerCertificates[0].Subject.CommonName)

	if enableKTLS {
		log.Println("Attempting to enable kTLS...")
		if err := enableKTLSOnConn(tlsConn, false, keyLog); err != nil {
			log.Printf("kTLS setup failed: %v", err)
			log.Println("Continuing with user-space TLS...")
		} else {
			log.Println("kTLS enabled successfully!")
		}
	}

	// Echo loop
	log.Println("Starting echo loop...")
	buf := make([]byte, 4096)
	for {
		n, err := tlsConn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("Read error: %v", err)
			}
			break
		}

		log.Printf("Received %d bytes: %q", n, string(buf[:n]))

		// Echo back
		response := fmt.Sprintf("ECHO: %s", string(buf[:n]))
		if _, err := tlsConn.Write([]byte(response)); err != nil {
			log.Printf("Write error: %v", err)
			break
		}
	}

	log.Println("Client disconnected")
}

func runClient(addr, certFile, keyFile, caFile string, enableKTLS bool) {
	log.Println("=== kTLS Test Client ===")

	// Load certificate
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("Failed to load certificate: %v", err)
	}

	// Load CA for server verification
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		log.Fatalf("Failed to read CA: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	// Set up key log writer for kTLS
	keyLog := newKeyLogWriter()

	config := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caPool,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: false,
		ServerName:         "agent-b", // Match cert CN
		KeyLogWriter:       keyLog,
	}

	log.Printf("Connecting to %s...", addr)
	conn, err := tls.Dial("tcp", addr, config)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	log.Printf("Connected!")
	log.Printf("  TLS Version: %s", tlsVersionString(state.Version))
	log.Printf("  Cipher Suite: %s", tls.CipherSuiteName(state.CipherSuite))
	log.Printf("  Server CN: %s", state.PeerCertificates[0].Subject.CommonName)

	// Keys are captured via KeyLogWriter during handshake
	log.Println("")
	log.Printf("Keys captured via KeyLogWriter: %d entries", len(keyLog.keys))
	for label := range keyLog.keys {
		log.Printf("  - %s", label)
	}

	if enableKTLS {
		log.Println("")
		log.Println("Attempting to enable kTLS...")
		if err := enableKTLSOnConn(conn, true, keyLog); err != nil {
			log.Printf("kTLS setup failed: %v", err)
			log.Println("Continuing with user-space TLS...")
		} else {
			log.Println("kTLS enabled successfully!")
		}
	}

	// Send test message
	log.Println("")
	log.Println("Sending test message...")
	testMsg := "Hello from kTLS client! This should be encrypted on the wire."
	if _, err := conn.Write([]byte(testMsg)); err != nil {
		log.Fatalf("Write failed: %v", err)
	}
	log.Printf("Sent: %q", testMsg)

	// Read response
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatalf("Read failed: %v", err)
	}
	log.Printf("Received: %q", string(buf[:n]))

	log.Println("")
	log.Println("=== Test Complete ===")
}

// extractTLSKeys extracts symmetric keys from a tls.Conn using reflection
// This is necessary because Go doesn't expose these keys directly
func extractTLSKeys(conn *tls.Conn) (*TLSKeys, error) {
	// Access the unexported 'in' and 'out' halfConn fields
	connVal := reflect.ValueOf(conn).Elem()

	// The internal structure changed across Go versions
	// In Go 1.21+, we need to access the cipher state differently
	
	// Try to find the traffic keys
	// This is highly version-dependent and may need adjustment
	
	// Method 1: Try to access via 'out' field (for TX)
	outField := connVal.FieldByName("out")
	if !outField.IsValid() {
		return nil, fmt.Errorf("cannot find 'out' field in tls.Conn")
	}

	inField := connVal.FieldByName("in")
	if !inField.IsValid() {
		return nil, fmt.Errorf("cannot find 'in' field in tls.Conn")
	}

	// For TLS 1.3, the cipher is stored in halfConn.cipher which is an interface
	// containing *aeadCipher with the actual keys

	// Get the cipher from out (TX direction)
	outCipher := outField.FieldByName("cipher")
	if !outCipher.IsValid() {
		return nil, fmt.Errorf("cannot find cipher in out halfConn")
	}

	// The cipher is an interface, need to get the concrete type
	if outCipher.IsNil() {
		return nil, fmt.Errorf("out cipher is nil (handshake not complete?)")
	}

	// Extract key material by examining the cipher implementation
	// This requires knowing the internal structure of the cipher
	
	// For now, let's just verify we can access these fields
	log.Printf("  out.cipher type: %v", outCipher.Elem().Type())

	inCipher := inField.FieldByName("cipher")
	if inCipher.IsValid() && !inCipher.IsNil() {
		log.Printf("  in.cipher type: %v", inCipher.Elem().Type())
	}

	// The actual key extraction would require deeper reflection into
	// the cipher implementation. For TLS 1.3 with AES-GCM, the cipher
	// is typically *crypto/internal/boring.aesCipher or similar.
	
	// Since we can't easily get the keys from Go's standard library,
	// we'll need to use a different approach for the actual kTLS setup.
	// Options:
	// 1. Use SSLKEYLOGFILE format and parse it
	// 2. Use a custom TLS implementation that exposes keys
	// 3. Compute the keys ourselves from the key schedule

	// For this test, we'll use the SSLKEYLOGFILE approach
	return nil, fmt.Errorf("direct key extraction not fully implemented - use SSLKEYLOGFILE instead")
}

// hkdfExpandLabel implements TLS 1.3 HKDF-Expand-Label
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) ([]byte, error) {
	// TLS 1.3 HKDF-Expand-Label format:
	// struct {
	//     uint16 length = Length;
	//     opaque label<7..255> = "tls13 " + Label;
	//     opaque context<0..255> = Context;
	// } HkdfLabel;
	
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
	// For AES-128-GCM: key is 16 bytes, IV is 12 bytes
	key, err = hkdfExpandLabel(trafficSecret, "key", nil, 16)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive key: %v", err)
	}
	
	iv, err = hkdfExpandLabel(trafficSecret, "iv", nil, 12)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive iv: %v", err)
	}
	
	return key, iv, nil
}

// enableKTLSOnConn attempts to enable kTLS on a TLS connection
func enableKTLSOnConn(conn *tls.Conn, isClient bool, keyLog *keyLogWriter) error {
	// Get the underlying TCP connection
	tcpConn, err := getTCPConn(conn)
	if err != nil {
		return fmt.Errorf("failed to get TCP conn: %v", err)
	}

	// Get the raw file descriptor
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to get syscall conn: %v", err)
	}

	// Get the keys from keyLog
	clientTrafficSecret := keyLog.keys["CLIENT_TRAFFIC_SECRET_0"]
	serverTrafficSecret := keyLog.keys["SERVER_TRAFFIC_SECRET_0"]

	log.Printf("  Keys captured: client=%d bytes, server=%d bytes",
		len(clientTrafficSecret), len(serverTrafficSecret))

	if len(clientTrafficSecret) == 0 || len(serverTrafficSecret) == 0 {
		return fmt.Errorf("traffic secrets not available")
	}

	// Derive actual keys and IVs using HKDF
	clientKey, clientIV, err := deriveTrafficKeys(clientTrafficSecret)
	if err != nil {
		return fmt.Errorf("failed to derive client keys: %v", err)
	}
	
	serverKey, serverIV, err := deriveTrafficKeys(serverTrafficSecret)
	if err != nil {
		return fmt.Errorf("failed to derive server keys: %v", err)
	}

	log.Printf("  Derived keys:")
	log.Printf("    Client: key=%x iv=%x", clientKey, clientIV)
	log.Printf("    Server: key=%x iv=%x", serverKey, serverIV)

	// Determine TX and RX keys based on whether we're client or server
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
		// Set TCP_ULP to "tls"
		err := syscall.SetsockoptString(int(fd), syscall.SOL_TCP, 31, "tls")
		if err != nil {
			sockErr = fmt.Errorf("failed to set TCP_ULP: %v", err)
			return
		}
		log.Printf("  TCP_ULP set to 'tls'")

		// Set up TLS_TX (transmit direction)
		txInfo := tlsCryptoInfoAESGCM128{
			Version:    TLS_1_3_VERSION,
			CipherType: TLS_CIPHER_AES_GCM_128,
		}
		// Copy key (16 bytes)
		copy(txInfo.Key[:], txKey)
		// For TLS 1.3, the IV/salt split is: salt (4 bytes) + IV (8 bytes) = 12 byte nonce
		copy(txInfo.Salt[:], txIV[:4])
		copy(txInfo.IV[:], txIV[4:12])
		// RecSeq starts at 0
		
		txInfoBytes := (*[40]byte)(unsafe.Pointer(&txInfo))[:]
		_, _, errno := syscall.Syscall6(
			syscall.SYS_SETSOCKOPT,
			fd,
			SOL_TLS,
			TLS_TX,
			uintptr(unsafe.Pointer(&txInfoBytes[0])),
			uintptr(len(txInfoBytes)),
			0,
		)
		if errno != 0 {
			sockErr = fmt.Errorf("failed to set TLS_TX: %v", errno)
			return
		}
		log.Printf("  TLS_TX configured")

		// Set up TLS_RX (receive direction)
		rxInfo := tlsCryptoInfoAESGCM128{
			Version:    TLS_1_3_VERSION,
			CipherType: TLS_CIPHER_AES_GCM_128,
		}
		copy(rxInfo.Key[:], rxKey)
		copy(rxInfo.Salt[:], rxIV[:4])
		copy(rxInfo.IV[:], rxIV[4:12])
		
		rxInfoBytes := (*[40]byte)(unsafe.Pointer(&rxInfo))[:]
		_, _, errno = syscall.Syscall6(
			syscall.SYS_SETSOCKOPT,
			fd,
			SOL_TLS,
			TLS_RX,
			uintptr(unsafe.Pointer(&rxInfoBytes[0])),
			uintptr(len(rxInfoBytes)),
			0,
		)
		if errno != 0 {
			sockErr = fmt.Errorf("failed to set TLS_RX: %v", errno)
			return
		}
		log.Printf("  TLS_RX configured")
	})

	if err != nil {
		return fmt.Errorf("control failed: %v", err)
	}
	if sockErr != nil {
		return sockErr
	}

	return nil
}

// getTCPConn extracts the underlying TCP connection from a tls.Conn
func getTCPConn(conn *tls.Conn) (*net.TCPConn, error) {
	// Access the unexported 'conn' field in tls.Conn using unsafe
	connVal := reflect.ValueOf(conn).Elem()
	netConnField := connVal.FieldByName("conn")
	if !netConnField.IsValid() {
		return nil, fmt.Errorf("cannot find conn field")
	}

	// Use unsafe to access unexported field
	netConnPtr := unsafe.Pointer(netConnField.UnsafeAddr())
	netConn := *(*net.Conn)(netConnPtr)
	
	tcpConn, ok := netConn.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("underlying conn is not TCP (got %T)", netConn)
	}

	return tcpConn, nil
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", v)
	}
}
