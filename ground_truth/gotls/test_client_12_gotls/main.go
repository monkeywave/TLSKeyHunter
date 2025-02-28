package main

import(
	"bufio"
	"os"
	"log"
	"crypto/tls"
)

func main() {
	log.SetFlags(log.Lshortfile)
	reader := bufio.NewReader(os.Stdin)
	server := "127.0.0.1:4432"

	// Wait for user to start
	start := bufio.NewReader(os.Stdin)
	log.Println("Press enter to proceed...")
	_, _ = start.ReadString('\n')

	conf := &tls.Config{
		// Don't verify the server's certificate
		InsecureSkipVerify: true,
		// Only use TLS 1.2
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
	}

	// Connect to the server via TCP and start a TLS handshake
	conn, err := tls.Dial("tcp", server, conf)
	if err != nil {
		log.Fatal(err)
		return;
	} else {
		log.Println("Connected to: ", server)
		log.Println("Press enter to exit")
		_, _ = reader.ReadString('\n')
	}
	defer conn.Close()
}