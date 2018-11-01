package proxy

import (
	"bufio"
	"fmt"
	"log"
	"net"

	"golang.org/x/crypto/ssh"
)

func StartTestSSHServer(httpServerURL, sshPrivateKey, userName string) string {
	if userName == "" {
		userName = "jumpbox"
	}

	signer, err := ssh.ParsePrivateKey([]byte(sshPrivateKey))
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() != userName {
				return nil, fmt.Errorf("unknown user: %q", c.User())
			}

			if string(signer.PublicKey().Marshal()) == string(pubKey.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("unknown public key for %q", c.User())
		},
	}

	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}

	go func() {
		for {
			nConn, err := listener.Accept()
			if err != nil {
				log.Fatal("failed to accept incoming connection: ", err)
			}

			_, chans, reqs, err := ssh.NewServerConn(nConn, config)
			if err != nil {
				log.Fatal("failed to handshake: ", err)
			}
			go ssh.DiscardRequests(reqs)

			for newChannel := range chans {
				if newChannel.ChannelType() != "direct-tcpip" {
					newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
					continue
				}
				channel, _, err := newChannel.Accept()
				if err != nil {
					log.Fatalf("Could not accept channel: %v", err)
				}
				defer channel.Close()

				data, err := bufio.NewReader(channel).ReadString('\n')
				if err != nil {
					log.Fatalf("Can't read data from channel: %v", err)
				}

				httpConn, err := net.Dial("tcp", httpServerURL)
				if err != nil {
					log.Fatalf("Could not open connection to http server: %v", err)
				}
				defer httpConn.Close()

				_, err = httpConn.Write([]byte(data + "\r\n\r\n"))
				if err != nil {
					log.Fatalf("Could not write to http server: %v", err)
				}

				data, err = bufio.NewReader(httpConn).ReadString('\n')
				if err != nil {
					log.Fatalf("Can't read data from http conn: %v", err)
				}

				_, err = channel.Write([]byte(data))
				if err != nil {
					log.Fatalf("Can't write data to channel: %v", err)
				}
			}
		}
	}()

	return listener.Addr().String()
}
