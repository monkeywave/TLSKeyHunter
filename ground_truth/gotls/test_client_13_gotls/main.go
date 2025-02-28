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
	server := "127.0.0.1:4433"

	// Wait for user to start
	start := bufio.NewReader(os.Stdin)
	log.Println("Press enter to proceed...")
	_, _ = start.ReadString('\n')

	conf := &tls.Config{
		// Don't verify the server's certificate
		InsecureSkipVerify: true,
		// Only use TLS 1.3
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
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