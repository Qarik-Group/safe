package proxy

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"

	socks5 "github.com/cloudfoundry/go-socks5"

	"log"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/context"
)

var netListen = net.Listen

type hostKey interface {
	Get(username, privateKey, serverURL string) (ssh.PublicKey, error)
}

type DialFunc func(network, address string) (net.Conn, error)

type Socks5Proxy struct {
	hostKey hostKey
	port    int
	started bool
	logger  *log.Logger
	mtx     sync.Mutex
}

func NewSocks5Proxy(hostKey hostKey, logger *log.Logger) *Socks5Proxy {
	return &Socks5Proxy{
		hostKey: hostKey,
		started: false,
		logger:  logger,
	}
}

func (s *Socks5Proxy) Start(username, key, url string) error {
	if s.isStarted() {
		return nil
	}

	dialer, err := s.Dialer(username, key, url)
	if err != nil {
		return err
	}

	err = s.StartWithDialer(dialer)
	if err != nil {
		return err
	}

	return nil
}

// thread safety
func (s *Socks5Proxy) isStarted() bool {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return s.started
}

func (s *Socks5Proxy) Dialer(username, key, url string) (DialFunc, error) {
	if username == "" {
		username = "jumpbox"
	}

	signer, err := ssh.ParsePrivateKey([]byte(key))
	if err != nil {
		return nil, fmt.Errorf("parse private key: %s", err)
	}

	hostKey, err := s.hostKey.Get(username, key, url)
	if err != nil {
		return nil, fmt.Errorf("get host key: %s", err)
	}

	clientConfig := NewSSHClientConfig(username, ssh.FixedHostKey(hostKey), ssh.PublicKeys(signer))

	conn, err := ssh.Dial("tcp", url, clientConfig)
	if err != nil {
		return nil, fmt.Errorf("ssh dial: %s", err)
	}

	return conn.Dial, nil
}

func (s *Socks5Proxy) StartWithDialer(dialer DialFunc) error {
	conf := &socks5.Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer(network, addr)
		},
		Logger: s.logger,
	}

	server, err := socks5.New(conf)
	if err != nil {
		return fmt.Errorf("new socks5 server: %s", err) // not tested
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()
	if s.port == 0 {
		s.port, err = openPort()
		if err != nil {
			return fmt.Errorf("open port: %s", err)
		}
	}

	go func() {
		server.ListenAndServe("tcp", fmt.Sprintf("127.0.0.1:%d", s.port))
	}()

	s.started = true
	return nil
}

func (s *Socks5Proxy) Addr() (string, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if s.port == 0 {
		return "", errors.New("socks5 proxy is not running")
	}
	return fmt.Sprintf("127.0.0.1:%d", s.port), nil
}

func openPort() (int, error) {
	l, err := netListen("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	defer l.Close()
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		return 0, err
	}

	return strconv.Atoi(port)
}
