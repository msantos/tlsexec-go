package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"syscall"
)

const (
	version = "0.1.0"
)

const (
	SO_REUSEPORT = 15
)

type stateT struct {
	argv    []string
	ipaddr  string
	cert    string
	key     string
	verbose bool
	tls     *tls.Config
}

func tlsconfig(cert, key string, strict bool) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}

	/*
	 * See:
	 * https://wiki.mozilla.org/Security/Server_Side_TLS
	 */

	/* TLS 1.2
	 * https://golang.org/src/crypto/tls/cipher_suites.go */
	ciphersuites := []uint16{
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{certificate},
	}

	if strict {
		config.MinVersion = tls.VersionTLS12
		config.CipherSuites = ciphersuites
	}

	return config, nil
}

func args() *stateT {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `%s v%s
Usage: %s [<ipaddr>]:<port> <command> [<...>]

Options:
`, path.Base(os.Args[0]), version, os.Args[0])
		flag.PrintDefaults()
	}

	cert := flag.String("cert", "cert.pem", "Path to TLS cert file")
	key := flag.String("key", "key.pem", "Path to TLS key file")
	verbose := flag.Bool("verbose", false,
		"Display service information")
	enableStrictTLS := flag.Bool("enable-strict-tls", true,
		"Restrict TLS protocols to TLS 1.2+ and use a reduced cipher suite for TLS 1.2")

	flag.Parse()

	if flag.NArg() < 2 {
		flag.Usage()
		os.Exit(1)
	}

	config, err := tlsconfig(*cert, *key, *enableStrictTLS)
	if err != nil {
		log.Printf("%s: %s", os.Args[0], err)
		os.Exit(1)
	}

	return &stateT{
		argv:    flag.Args()[1:],
		ipaddr:  flag.Arg(0),
		cert:    *cert,
		key:     *key,
		verbose: *verbose,
		tls:     config,
	}
}

func main() {
	state := args()

	exe := state.argv[0]
	argv := state.argv[1:]

	arg0, err := exec.LookPath(exe)
	if err != nil {
		log.Printf("%s: %s\n", os.Args[0], err)
		os.Exit(127)
	}

	conn, err := state.listen()
	if err != nil {
		log.Printf("listen: %s\n", err)
		os.Exit(111)
	}

	if err := setenv(conn); err != nil {
		log.Printf("setenv: %s\n", err)
		os.Exit(111)
	}

	os.Exit(execv(conn, arg0, argv, os.Environ()))
}

func (state *stateT) listen() (net.Conn, error) {
	config := &net.ListenConfig{Control: soReusePort}
	socket, err := config.Listen(context.Background(), "tcp", state.ipaddr)
	if err != nil {
		return nil, err
	}
	listener := tls.NewListener(socket, state.tls)
	return listener.Accept()
}

func soReusePort(network, address string, conn syscall.RawConn) (err error) {
	f := func(fd uintptr) {
		err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1)
	}
	if err := conn.Control(f); err != nil {
		return err
	}
	return err
}

func setenv(conn net.Conn) error {
	lhost, lport, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return err
	}
	rhost, rport, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return err
	}

	// https://jdebp.eu/FGA/UCSPI.html
	//
	// SSLLOCALIP
	// the IP address of the local host, in standard human-readable form
	// SSLLOCALPORT
	// the local SSL port number, in decimal
	// SSLLOCALHOST
	// a name listed in the DNS for the local host, unset if no such name is available/obtained
	// SSLREMOTEIP
	// the IP address of the remote host, in standard human-readable form
	// SSLREMOTEPORT
	// the remote SSL port number, in decimal
	// SSLREMOTEHOST
	// a name listed in the DNS for the remote host, unset if no such name is available/obtained
	// SSLREMOTEINFO
	// a string supplied by the remote host for the connection
	// at hand via the 931/1413/IDENT/TAP protocol, unset if none is
	// available/obtained
	env := map[string]string{
		"SSLLOCALHOST":  "",
		"SSLREMOTEHOST": "",
		"SSLREMOTEINFO": "",
		"PROTO":         "SSL",
		"SSLLOCALIP":    lhost,
		"SSLLOCALPORT":  lport,
		"SSLREMOTEIP":   rhost,
		"SSLREMOTEPORT": rport,
	}

	for k, v := range env {
		if v == "" {
			if err := os.Unsetenv(k); err != nil {
				return err
			}
			continue
		}
		if err := os.Setenv(k, v); err != nil {
			return err
		}
	}

	return nil
}

func execv(conn net.Conn, command string, args []string, env []string) int {
	cmd := exec.Command(command, args...)
	cmd.Stdin = conn
	cmd.Stdout = conn
	cmd.Stderr = os.Stderr
	cmd.Env = env

	if err := cmd.Start(); err != nil {
		log.Printf("%s: %s\n", os.Args[0], err)
		return 127
	}
	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
		close(waitCh)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGQUIT,
		syscall.SIGTERM,
		syscall.SIGUSR1,
		syscall.SIGUSR2,
	)

	for {
		select {
		case sig := <-sigCh:
			_ = cmd.Process.Signal(sig)
		case err := <-waitCh:
			if err == nil {
				return 0
			}

			var exitError *exec.ExitError
			if errors.As(err, &exitError) {
				if waitStatus, ok := exitError.Sys().(syscall.WaitStatus); ok {
					if waitStatus.Signaled() {
						return 128 + int(waitStatus.Signal())
					}
					return waitStatus.ExitStatus()
				}
			}

			log.Printf("%s: %s", os.Args[0], err)
			return 111
		}
	}
}
