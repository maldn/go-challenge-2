package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"
)

func TestRealKeys(t *testing.T) {
	bob_pub, bob_priv, _ := box.GenerateKey(rand.Reader)
	alice_pub, alice_priv, _ := box.GenerateKey(rand.Reader)

	//shared = box.Precompute(sharedKey, peersPublicKey, privateKey)
	var nonce [24]byte
	rand.Read(nonce[:])

	bobs_message := "hi from bob"
	bobs_box := box.Seal(nil, []byte(bobs_message), &nonce, alice_pub, bob_priv)
	decrypted, success := box.Open(nil, bobs_box, &nonce, bob_pub, alice_priv)

	if success != true || string(decrypted) != bobs_message {
		t.Fatalf("error decrypting.\nexpected '%s'\ngot '%s'", string(decrypted), bobs_message)
	}

	alices_message := "re from alice"
	alices_box := box.Seal(nil, []byte(alices_message), &nonce, bob_pub, alice_priv)
	decrypted, success = box.Open(nil, alices_box, &nonce, alice_pub, bob_priv)

	if success != true || string(decrypted) != alices_message {
		t.Fatalf("error decrypting.\nexpected '%s'\ngot '%s'", string(decrypted), alices_message)
	}
}

func TestReadWriterPing(t *testing.T) {
	//alice sends bob the message.
	bob_pub, bob_priv, _ := box.GenerateKey(rand.Reader)
	alice_pub, alice_priv, _ := box.GenerateKey(rand.Reader)

	//priv, pub := &[32]byte{'p', 'r', 'i', 'v'}, &[32]byte{'p', 'u', 'b'}
	r, w := io.Pipe()
	secureR := NewSecureReader(r, bob_priv, alice_pub)
	secureW := NewSecureWriter(w, alice_priv, bob_pub)

	// Encrypt hello world
	go func() {
		fmt.Fprintf(secureW, "hello world\n")
		w.Close()
	}()

	// Decrypt message
	buf := make([]byte, 102)
	n, err := secureR.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	buf = buf[:n]

	// Make sure we have hello world back
	if res := string(buf); res != "hello world\n" {
		t.Fatalf("Unexpected result: %v != %s", []byte(res), "hello world")
	}
}

func TestSecureWriter(t *testing.T) {
	priv, pub := &[32]byte{'p', 'r', 'i', 'v'}, &[32]byte{'p', 'u', 'b'}

	r, w := io.Pipe()
	secureW := NewSecureWriter(w, priv, pub)

	// Make sure we are secure
	// Encrypt hello world
	go func() {
		fmt.Fprintf(secureW, "hello world\n")
		w.Close()
	}()

	// Read from the underlying transport instead of the decoder
	buf, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	// Make sure we dont' read the plain text message.
	if res := string(buf); res == "hello world\n" {
		t.Fatal("Unexpected result. The message is not encrypted.")
	}

	r, w = io.Pipe()
	secureW = NewSecureWriter(w, priv, pub)

	// Make sure we are unique
	// Encrypt hello world
	go func() {
		fmt.Fprintf(secureW, "hello world\n")
		w.Close()
	}()

	// Read from the underlying transport instead of the decoder
	buf2, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	// Make sure we dont' read the plain text message.
	if string(buf) == string(buf2) {
		t.Fatal("Unexpected result. The encrypted message is not unique.")
	}

}

func TestSecureEchoServer(t *testing.T) {
	// Create a random listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Start the server
	go Serve(l)

	conn, err := Dial(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	expected := "hello world\n"
	if _, err := fmt.Fprintf(conn, expected); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}

	if got := string(buf[:n]); got != expected {
		t.Fatalf("Unexpected result:%#v\n", buf)
		t.Fatalf("Unexpected result:\nGot:\t\t%s\nExpected:\t%s\n", got, expected)
	}
}

func TestSecureServe(t *testing.T) {
	// Create a random listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Start the server
	go Serve(l)

	conn, err := net.DialTimeout("tcp", l.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}

	unexpected := "hello world\n"
	if _, err := fmt.Fprintf(conn, unexpected); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}

	if got := string(buf[:n]); got == unexpected {
		t.Fatalf("Unexpected result:\nGot raw data instead of serialized key")
	}
}

func TestSecureDial(t *testing.T) {
	// Create a random listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Start the server
	go func(l net.Listener) {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				key := [32]byte{}
				c.Write(key[:])
				buf := make([]byte, 2048)
				n, err := c.Read(buf)
				if err != nil && err != io.EOF {
					t.Fatal(err)
				}
				if got := string(buf[:n]); got == "hello world\n" {
					t.Fatal("Unexpected result. Got raw data instead of encrypted")
				}
			}(conn)
		}
	}(l)

	conn, err := Dial(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	expected := "hello world\n"
	if _, err := fmt.Fprintf(conn, expected); err != nil {
		t.Fatal(err)
	}
}
