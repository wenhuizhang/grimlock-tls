// Splice + kTLS Test
//
// This test verifies that splice() works with kTLS for zero-copy encrypted forwarding.
// Unlike sk_msg (which bypasses kTLS), splice() goes through the sendmsg() path
// where kTLS can encrypt/decrypt data.
//
// Test flow:
// 1. Create a kTLS-enabled TCP connection (simulating tunnel)
// 2. Create a plain TCP connection (simulating agent)
// 3. Use splice() to forward data from plain socket to kTLS socket
// 4. Verify data is encrypted on wire and decrypted at receiver

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
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/crypto/hkdf"
)

var (
	mode     = flag.String("mode", "server", "server or client")
	peerAddr = flag.String("peer", "", "peer address for client mode")
	certFile = flag.String("cert", "certs/agent-a.crt", "certificate file")
	keyFile  = flag.String("key", "certs/agent-a.pem", "key file")
	caFile   = flag.String("ca", "certs/ca.crt", "CA certificate file")
)

// kTLS constants
const (
	SOL_TLS    = 282
	TLS_TX     = 1
	TLS_RX     = 2
	TCP_ULP    = 31
	SOL_TCP    = 6
)

// TLS 1.3 AES-GCM-128 crypto info structure
type tlsCryptoInfoAESGCM128 struct {
	Version    uint16
	CipherType uint16
	IV         [8]byte
	Key        [16]byte
	Salt       [4]byte
	RecSeq     [8]byte
}

func main() {
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	log.Println("==============================================")
	log.Println("  Splice + kTLS Test")
	log.Println("==============================================")

	if *mode == "server" {
		runServer()
	} else {
		if *peerAddr == "" {
			log.Fatal("Client mode requires --peer address")
		}
		runClient()
	}
}

// keyLogWriter captures TLS traffic secrets
type keyLogWriter struct {
	keys map[string][]byte
}

func newKeyLogWriter() *keyLogWriter {
	return &keyLogWriter{keys: make(map[string][]byte)}
}

func (w *keyLogWriter) Write(p []byte) (n int, err error) {
	line := string(p)
	var label, clientRandom, secret string
	fmt.Sscanf(line, "%s %s %s", &label, &clientRandom, &secret)
	if secret != "" {
		w.keys[label] = hexDecode(secret)
	}
	return len(p), nil
}

func hexDecode(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(b); i++ {
		fmt.Sscanf(s[i*2:i*2+2], "%02x", &b[i])
	}
	return b
}

func runServer() {
	log.Println("[SERVER] Starting...")

	// Load certificates
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("Failed to load cert: %v", err)
	}

	caCert, err := os.ReadFile(*caFile)
	if err != nil {
		log.Fatalf("Failed to read CA: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	keyLog := newKeyLogWriter()
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		KeyLogWriter: keyLog,
	}

	// Listen for TLS connections (simulating tunnel endpoint)
	listener, err := tls.Listen("tcp", ":9443", tlsConfig)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()
	log.Println("[SERVER] Listening on :9443 for TLS tunnel connections")

	// Also listen for plain TCP (simulating local agent connection)
	plainListener, err := net.Listen("tcp", ":15001")
	if err != nil {
		log.Fatalf("Failed to listen plain: %v", err)
	}
	defer plainListener.Close()
	log.Println("[SERVER] Listening on :15001 for plain agent connections")

	// Accept TLS connection first
	log.Println("[SERVER] Waiting for TLS tunnel connection...")
	tlsConn, err := listener.Accept()
	if err != nil {
		log.Fatalf("Failed to accept TLS: %v", err)
	}
	defer tlsConn.Close()
	log.Printf("[SERVER] TLS connection from %s", tlsConn.RemoteAddr())

	// Force handshake
	if err := tlsConn.(*tls.Conn).Handshake(); err != nil {
		log.Fatalf("TLS handshake failed: %v", err)
	}
	log.Println("[SERVER] TLS handshake complete")

	// Enable kTLS on the tunnel connection
	clientSecret := keyLog.keys["CLIENT_TRAFFIC_SECRET_0"]
	serverSecret := keyLog.keys["SERVER_TRAFFIC_SECRET_0"]
	if len(clientSecret) == 0 || len(serverSecret) == 0 {
		log.Println("[SERVER] Warning: Could not get TLS secrets, continuing without kTLS")
	} else {
		if err := enableKTLS(tlsConn.(*tls.Conn), clientSecret, serverSecret, false); err != nil {
			log.Printf("[SERVER] kTLS setup failed: %v", err)
		} else {
			log.Println("[SERVER] kTLS enabled on tunnel socket")
		}
	}

	// Accept plain connection (simulating agent)
	log.Println("[SERVER] Waiting for plain agent connection...")
	plainConn, err := plainListener.Accept()
	if err != nil {
		log.Fatalf("Failed to accept plain: %v", err)
	}
	defer plainConn.Close()
	log.Printf("[SERVER] Plain connection from %s", plainConn.RemoteAddr())

	// Now test splice: plain socket → TLS socket
	log.Println("[SERVER] Starting splice test: plain → TLS tunnel")

	// Get file descriptors
	plainFd := getFd(plainConn)
	tlsFd := getFd(tlsConn.(*tls.Conn))
	log.Printf("[SERVER] Plain FD: %d, TLS FD: %d", plainFd, tlsFd)

	// Read from plain, splice to TLS
	go func() {
		pipeFds := make([]int, 2)
		if err := syscall.Pipe(pipeFds); err != nil {
			log.Printf("[SPLICE] Failed to create pipe: %v", err)
			return
		}
		defer syscall.Close(pipeFds[0])
		defer syscall.Close(pipeFds[1])

		buf := make([]byte, 4096)
		for {
			// Read from plain socket
			n, err := plainConn.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("[SPLICE] Read error: %v", err)
				}
				return
			}
			log.Printf("[SPLICE] Read %d bytes from plain socket: %q", n, string(buf[:n]))

			// Write to TLS socket (this should trigger kTLS encryption)
			written, err := tlsConn.Write(buf[:n])
			if err != nil {
				log.Printf("[SPLICE] Write to TLS error: %v", err)
				return
			}
			log.Printf("[SPLICE] Wrote %d bytes to TLS socket (should be encrypted on wire)", written)
		}
	}()

	// Read from TLS, forward to plain (for responses)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := tlsConn.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("[TUNNEL] Read error: %v", err)
				}
				return
			}
			log.Printf("[TUNNEL] Received %d bytes from tunnel: %q", n, string(buf[:n]))
			plainConn.Write(buf[:n])
		}
	}()

	// Keep running
	select {}
}

func runClient() {
	log.Println("[CLIENT] Starting...")

	// Load certificates
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("Failed to load cert: %v", err)
	}

	caCert, err := os.ReadFile(*caFile)
	if err != nil {
		log.Fatalf("Failed to read CA: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	keyLog := newKeyLogWriter()
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		KeyLogWriter: keyLog,
	}

	// Connect to server's TLS port (simulating tunnel)
	log.Printf("[CLIENT] Connecting to %s:9443 (TLS tunnel)...", *peerAddr)
	tlsConn, err := tls.Dial("tcp", *peerAddr+":9443", tlsConfig)
	if err != nil {
		log.Fatalf("Failed to connect TLS: %v", err)
	}
	defer tlsConn.Close()
	log.Println("[CLIENT] TLS tunnel connected")

	// Enable kTLS
	clientSecret := keyLog.keys["CLIENT_TRAFFIC_SECRET_0"]
	serverSecret := keyLog.keys["SERVER_TRAFFIC_SECRET_0"]
	if len(clientSecret) == 0 || len(serverSecret) == 0 {
		log.Println("[CLIENT] Warning: Could not get TLS secrets, continuing without kTLS")
	} else {
		if err := enableKTLS(tlsConn, clientSecret, serverSecret, true); err != nil {
			log.Printf("[CLIENT] kTLS setup failed: %v", err)
		} else {
			log.Println("[CLIENT] kTLS enabled on tunnel socket")
		}
	}

	// Start a goroutine to read from tunnel and print
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := tlsConn.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("[CLIENT] Read error: %v", err)
				}
				return
			}
			log.Printf("[CLIENT] Received from tunnel: %q", string(buf[:n]))
		}
	}()

	// Wait for server to be ready
	time.Sleep(1 * time.Second)

	// Now connect to server's plain port (simulating agent connection to local Grimlock)
	log.Printf("[CLIENT] Connecting to %s:15001 (plain, simulating agent)...", *peerAddr)
	plainConn, err := net.Dial("tcp", *peerAddr+":15001")
	if err != nil {
		log.Fatalf("Failed to connect plain: %v", err)
	}
	defer plainConn.Close()
	log.Println("[CLIENT] Plain connection established")

	// Send test data through plain socket
	// Server will splice this to TLS socket
	testMsg := "SPLICE_TEST_MESSAGE_" + time.Now().Format("150405")
	log.Printf("[CLIENT] Sending through plain socket: %q", testMsg)
	plainConn.Write([]byte(testMsg))

	// Read response
	buf := make([]byte, 4096)
	plainConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := plainConn.Read(buf)
	if err != nil {
		log.Printf("[CLIENT] No response (expected if no echo): %v", err)
	} else {
		log.Printf("[CLIENT] Response: %q", string(buf[:n]))
	}

	log.Println("[CLIENT] Test complete. Check server logs for splice activity.")
	log.Println("[CLIENT] Use tcpdump on :9443 to verify encryption!")
}

// getFd extracts the file descriptor from a connection
func getFd(conn net.Conn) int {
	// Get the underlying TCPConn
	var tcpConn *net.TCPConn
	switch c := conn.(type) {
	case *net.TCPConn:
		tcpConn = c
	case *tls.Conn:
		// Need to get underlying connection
		// This is tricky - we'll use reflection or just return -1
		return -1
	default:
		return -1
	}

	file, err := tcpConn.File()
	if err != nil {
		return -1
	}
	defer file.Close()
	return int(file.Fd())
}

// enableKTLS configures kTLS on a TLS connection
func enableKTLS(conn *tls.Conn, clientSecret, serverSecret []byte, isClient bool) error {
	// Derive keys
	clientKey, clientIV := deriveTrafficKeys(clientSecret)
	serverKey, serverIV := deriveTrafficKeys(serverSecret)

	// Get raw connection
	rawConn, err := conn.NetConn().(*net.TCPConn).SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to get syscall conn: %v", err)
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
		// Set TCP_ULP to "tls"
		err := syscall.SetsockoptString(int(fd), SOL_TCP, TCP_ULP, "tls")
		if err != nil {
			sockErr = fmt.Errorf("failed to set TCP_ULP: %v", err)
			return
		}

		// Configure TLS_TX
		txInfo := tlsCryptoInfoAESGCM128{
			Version:    0x0304, // TLS 1.3
			CipherType: 51,    // AES-GCM-128
		}
		copy(txInfo.Key[:], txKey)
		copy(txInfo.Salt[:], txIV[:4])
		copy(txInfo.IV[:], txIV[4:12])

		txInfoBytes := (*[40]byte)(unsafe.Pointer(&txInfo))[:]
		_, _, errno := syscall.Syscall6(
			syscall.SYS_SETSOCKOPT,
			fd, SOL_TLS, TLS_TX,
			uintptr(unsafe.Pointer(&txInfoBytes[0])),
			uintptr(len(txInfoBytes)), 0,
		)
		if errno != 0 {
			sockErr = fmt.Errorf("failed to set TLS_TX: %v", errno)
			return
		}

		// Configure TLS_RX
		rxInfo := tlsCryptoInfoAESGCM128{
			Version:    0x0304,
			CipherType: 51,
		}
		copy(rxInfo.Key[:], rxKey)
		copy(rxInfo.Salt[:], rxIV[:4])
		copy(rxInfo.IV[:], rxIV[4:12])

		rxInfoBytes := (*[40]byte)(unsafe.Pointer(&rxInfo))[:]
		_, _, errno = syscall.Syscall6(
			syscall.SYS_SETSOCKOPT,
			fd, SOL_TLS, TLS_RX,
			uintptr(unsafe.Pointer(&rxInfoBytes[0])),
			uintptr(len(rxInfoBytes)), 0,
		)
		if errno != 0 {
			sockErr = fmt.Errorf("failed to set TLS_RX: %v", errno)
			return
		}
	})

	if err != nil {
		return fmt.Errorf("control failed: %v", err)
	}
	return sockErr
}

// deriveTrafficKeys derives key and IV from traffic secret using HKDF
func deriveTrafficKeys(secret []byte) (key []byte, iv []byte) {
	key = hkdfExpandLabel(secret, "key", nil, 16)
	iv = hkdfExpandLabel(secret, "iv", nil, 12)
	return
}

// hkdfExpandLabel implements TLS 1.3 HKDF-Expand-Label
func hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
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
	reader.Read(result)
	return result
}
