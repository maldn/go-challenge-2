package main

import (
	"crypto/rand"
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
	//out would be appended to, but we always encrypt a new message (for now)
	var enc []byte
	n, err = sr.r.Read(p)
	var nonce [24]byte
	rand.Read(nonce[:])
	copy(enc, p[:n])
	//nonce = [24]byte{'1'}
	p = p[:28]
	dec, foo := box.Open(enc, p, &nonce, sr.pub, sr.priv)
	fmt.Printf("%v\n%v\n%v\n%v\n", foo, p, enc, dec)
	return n, err
	/*
		var nonce [24]byte
		rand.Read(nonce[:])
		encrypted := box.Seal(out, p, &nonce, sw.pub, sw.priv)
		// write to underlying writer
		return sw.w.Write(encrypted)

		return sr.r.Read(p)*/
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
	//out would be appended to, but we always encrypt a new message (for now)
	var out []byte
	var nonce [24]byte
	rand.Read(nonce[:])
	nonce = [24]byte{'1'}
	encrypted := box.Seal(out, p, &nonce, sw.pub, sw.priv)
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
	return nil, nil
}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	return nil
}

func main() {
	app := cli.NewApp()
	app.Name = "greet"
	app.Usage = "fight the loneliness!"
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
