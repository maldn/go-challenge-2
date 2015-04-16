package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/codegangsta/cli"
	"golang.org/x/crypto/nacl/box"
)

type SecureReader struct {
	r         io.Reader
	priv, pub *[32]byte
}

// TODO pack nonce and actual encrypted message into one struct. encoding/binary
func (sr *SecureReader) Read(p []byte) (n int, err error) {
	// read encrypted message from onderlying reader
	var buf = make([]byte, 1024)
	n, err = sr.r.Read(buf)
	if err != nil {
		return n, err
	}
	fmt.Printf("READ: %#v\n", buf[:n])
	//first 24 bytes is our nonce, rest is message
	var nonce [24]byte
	copy(nonce[:], buf[:24])
	decrypted, success := box.Open(nil, buf[24:n], &nonce, sr.pub, sr.priv)
	fmt.Printf("READ:\n\tnonce: %#v\n\tenc: %#v\n\tplain: '%s'\n\t%#v\n\t%#v\n\n", nonce, buf[24:n], decrypted, sr.pub, sr.priv)
	if success != true {
		log.Fatalln("Error decrypting message")
	}
	copy(p, decrypted)
	fmt.Printf("\n\n##########DECRYPT: %s\n%#v\n\n", p, decrypted)
	return len(decrypted), err
}

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	return &SecureReader{priv: priv, pub: pub, r: r}
}

type SecureWriter struct {
	w         io.Writer
	priv, pub *[32]byte
}

func (sw *SecureWriter) Write(p []byte) (n int, err error) {
	//each "packet" starts with the nonce followed by the message
	var nonce [24]byte
	rand.Read(nonce[:])

	encrypted := box.Seal(nonce[:], p, &nonce, sw.pub, sw.priv)
	fmt.Printf("Write:\n\tnonce: %#v\n\tenc: %#v\n\tplain: '%s'\n\t%#v\n\t%#v\n\n", nonce, encrypted[24:], p, sw.pub, sw.priv)
	// write to underlying writer
	return sw.w.Write(encrypted)
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	return &SecureWriter{priv: priv, pub: pub, w: w}

}

type SecureConn struct {
	conn io.ReadWriteCloser
	r    io.Reader
	w    io.Writer
}

func NewSecureConn(c io.ReadWriteCloser, priv, pub, peer_pub *[32]byte) io.ReadWriteCloser {
	return &SecureConn{
		conn: c,
		r:    NewSecureReader(c, priv, pub),
		w:    NewSecureWriter(c, priv, peer_pub),
	}
}

func (rwc *SecureConn) Read(p []byte) (n int, err error) {
	return rwc.r.Read(p)
}

func (rwc *SecureConn) Write(p []byte) (n int, err error) {
	return rwc.w.Write(p)
}

func (rwc *SecureConn) Close() error {
	return rwc.conn.Close()
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	client_pub, client_priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)

	//fmt.Printf("Dial: sending client public key: %#v\n", client_pub)
	n, err := conn.Write(client_pub[:])
	if err != nil {
		return nil, err
	}

	var server_pub [32]byte
	n, err = conn.Read(server_pub[:])
	if err != nil {
		return nil, err
	}
	//fmt.Printf("Dial: got server public key: %#v\n", server_pub)
	if n != 32 {
		return nil, fmt.Errorf("excpected to read 32 bytes, got %d", n)
	}
	return NewSecureConn(conn, client_priv, client_pub, &server_pub), nil
}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	server_pub, server_priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			//fmt.Printf("Serve: sending server public key: %#v\n", server_pub)
			c.Write(server_pub[:])

			var peer_pub [32]byte
			c.Read(peer_pub[:])
			//fmt.Printf("Serve: reading client public key: %#v\n", peer_pub)
			sc := NewSecureConn(c, server_priv, server_pub, &peer_pub)
			defer sc.Close()
			//client_pub
			//for {
			//buf := make([]byte, 32*1024)
			//n, err := sc.Read(buf)
			//sc.Write
			//echo
			io.Copy(sc, sc)
			//}
		}(conn)
	}
}

func main() {
	app := cli.NewApp()
	app.Name = "go-challenge-2"
	app.Usage = "mooh"
	app.Author = "Malte 'maldn' Böhme <malte.boehme@googlemail.com>"
	app.Commands = []cli.Command{
		{
			Name:    "generate-keys",
			Aliases: []string{"g", "gen"},
			Usage:   "generate private and public keys",
			Action: func(c *cli.Context) {
				pub, priv, err := box.GenerateKey(rand.Reader)
				if err != nil {
					log.Fatal(err)
				}
				log.Printf("pub: %#v\npriv: %#vs\n", pub, priv)
			},
		},
		{
			Name:        "listen",
			Aliases:     []string{"c"},
			Usage:       "listen <port>",
			Description: "listens for encrypted messages",
			Action: func(c *cli.Context) {
				p, err := strconv.ParseInt(c.Args().First(), 10, 16)
				if err != nil {
					log.Fatalf("invalid port")
				}
				println("choosen port: ", p)
				l, err := net.Listen("tcp", fmt.Sprintf(":%d", p))
				if err != nil {
					log.Fatal(err)
				}
				defer l.Close()
				log.Fatal(Serve(l))
			},
		},
	}

	app.Run(os.Args)
	/*
		port := flag.Int("l", 0, "Listen mode. Specify port")
		flag.Parse()

		// Server mode
		if *port != 0 {
			l, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
			if err != nil {
				log.Fatal(err)
			}
			defer l.Close()
			log.Fatal(Serve(l))
		}

		// Client mode
		if len(os.Args) != 3 {
			log.Fatalf("Usage: %s <port> <message>", os.Args[0])
		}
		conn, err := Dial("localhost:" + os.Args[1])
		if err != nil {
			log.Fatal(err)
		}
		if _, err := conn.Write([]byte(os.Args[2])); err != nil {
			log.Fatal(err)
		}
		buf := make([]byte, len(os.Args[2]))
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			log.Fatal(err)
		}
		fmt.Printf("%s\n", buf[:n])
	*/
}
