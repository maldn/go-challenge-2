package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"

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
	n, err = sr.r.Read(p)
	if err != nil {
		return n, err
	}
	//first 24 bytes is our nonce, rest is message
	var nonce [24]byte
	copy(nonce[:], p[:24])
	decrypted, success := box.Open(nil, p[24:n], &nonce, sr.pub, sr.priv)
	if success != true {
		return 0, errors.New("Error decrypting message")
	}
	copy(p, decrypted)
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

type RWC struct {
	SecureReader
	SecureWriter
}

func (sw *SecureWriter) Write(p []byte) (n int, err error) {
	//each "packet" starts with the nonce followed by the message
	var nonce [24]byte
	rand.Read(nonce[:])

	encrypted := box.Seal(nonce[:], p, &nonce, sw.pub, sw.priv)
	//fmt.Printf("WRITE: %v\n\t%v\n", encrypted, p)
	// write to underlying writer
	return sw.w.Write(encrypted)
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	return &SecureWriter{priv: priv, pub: pub, w: w}

}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	_, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {

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
