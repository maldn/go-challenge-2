package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/nacl/box"
)

type SecureReader struct {
	r         io.Reader
	priv, pub *[32]byte
}

func (sr *SecureReader) Read(p []byte) (n int, err error) {
	// read encrypted message from underlying reader
	var buf = make([]byte, 1024)
	n, err = sr.r.Read(buf)
	if err != nil {
		return n, err
	}
	//first 24 bytes is our nonce, rest is message
	var nonce [24]byte
	copy(nonce[:], buf[:24])

	decrypted, success := box.Open(nil, buf[24:n], &nonce, sr.pub, sr.priv)
	if success != true {
		return 0, fmt.Errorf("Error decrypting message")
	}

	/*
		fmt.Printf(`
			//READ
			var nonce = %#v
			var enc = %#v
			//plain: '%s'
			var peer_pub = %#v
			var priv = %#v`, nonce, buf[24:n], decrypted, sw.pub, sw.priv)
	*/

	//copy to output buffer
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

func (sw *SecureWriter) Write(p []byte) (n int, err error) {
	//each "packet" starts with the nonce followed by the message
	var nonce [24]byte
	//so lets generate a random one for this packet
	rand.Read(nonce[:])
	//and seal the message with our private and their public key
	//Seal() appends the encrypted msg to our nonce (first arg)
	encrypted := box.Seal(nonce[:], p, &nonce, sw.pub, sw.priv)

	/*
		fmt.Printf(`
			//WRITE
			var nonce = %#v
			var enc = %#v
			//plain: '%s'
			var peer_pub = %#v
			var priv = %#v`, nonce, encrypted[24:], p, sw.pub, sw.priv)
	*/
	// write to underlying writer
	return sw.w.Write(encrypted)
}

func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	return &SecureWriter{priv: priv, pub: pub, w: w}

}

type SecureConn struct {
	conn io.ReadWriteCloser
	r    io.Reader
	w    io.Writer
}

func NewSecureConn(conn io.ReadWriteCloser, priv, pub *[32]byte) io.ReadWriteCloser {
	return &SecureConn{
		conn: conn,
		r:    NewSecureReader(conn, priv, pub),
		w:    NewSecureWriter(conn, priv, pub),
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
	if err != nil {
		return nil, err
	}

	//fmt.Printf("Dial: sending client public key: %#v\n", client_pub)
	n, err := conn.Write(client_pub[:])
	if err != nil {
		return nil, err
	}
	if n != len(client_pub) {
		return nil, fmt.Errorf("Dial: Couldn't fully write client public key. %d bytes written", n)
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
	return NewSecureConn(conn, client_priv, &server_pub), nil
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
			c.Write(server_pub[:])

			var client_pub [32]byte
			c.Read(client_pub[:])
			sc := NewSecureConn(c, server_priv, &client_pub)
			defer sc.Close()
			// for now we are just copying
			for {
				io.Copy(sc, sc)
			}
			//for {
			//buf := make([]byte, 32*1024)
			//n, err := sc.Read(buf)
			//sc.Write(buf)
			//}
		}(conn)
	}
}

func main() {
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

	/*
		if *pingpong {
			ticker := time.NewTicker(time.Second * 1)
			for _ = range ticker.C {
				t := time.Now().Format("2006-01-02 15:04:05")
				if _, err := conn.Write([]byte(t)); err != nil {
					log.Fatal(err)
				}
				fmt.Printf("PING: '%s'\n", t)
				buf := make([]byte, len([]byte(t)))
				n, err := conn.Read(buf)
				if err != nil && err != io.EOF {
					log.Fatal(err)
				}
				fmt.Printf("PONG: '%s'\n", buf[:n])
			}
		}
	*/
}
