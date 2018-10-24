package snihost

import (
	"log"
	"net"
)

func ParseSNIHost(conn net.Conn) (hostname string, bodydata []byte) {
	// Simple SNI Protocol : SNI Handling Code from https://github.com/gpjt/stupid-proxy/
	firstByte := make([]byte, 1)
	_, error := conn.Read(firstByte)
	if error != nil {
		log.Printf("Couldn't read first byte :-(")
		return
	}
	if firstByte[0] != 0x16 {
		log.Printf("Not TLS :-(")
	}

	versionBytes := make([]byte, 2)
	_, error = conn.Read(versionBytes)
	if error != nil {
		log.Printf("Couldn't read version bytes :-(")
		return
	}
	if versionBytes[0] < 3 || (versionBytes[0] == 3 && versionBytes[1] < 1) {
		log.Printf("SSL < 3.1 so it's still not TLS v%d.%d", versionBytes[0], versionBytes[1])
		return
	}

	restLengthBytes := make([]byte, 2)
	_, error = conn.Read(restLengthBytes)
	if error != nil {
		log.Printf("Couldn't read restLength bytes :-(")
		return
	}
	restLength := (int(restLengthBytes[0]) << 8) + int(restLengthBytes[1])

	rest := make([]byte, restLength)
	_, error = conn.Read(rest)
	if error != nil {
		log.Printf("Couldn't read rest of bytes")
		return
	}

	current := 0

	handshakeType := rest[0]

	current += 1
	if handshakeType != 0x1 {
		log.Printf("Not a ClientHello")
		return
	}

	// Skip over another length
	current += 3
	// Skip over protocolversion
	current += 2
	// Skip over random number
	current += 4 + 28
	// Skip over session ID
	sessionIDLength := int(rest[current])
	current += 1
	current += sessionIDLength

	cipherSuiteLength := (int(rest[current]) << 8) + int(rest[current+1])
	current += 2
	current += cipherSuiteLength

	compressionMethodLength := int(rest[current])
	current += 1
	current += compressionMethodLength

	if current > restLength {
		log.Println("no extensions")
		return
	}

	// Skip over extensionsLength
	// extensionsLength := (int(rest[current]) << 8) + int(rest[current + 1])
	current += 2

	for current < restLength && hostname == "" {
		extensionType := (int(rest[current]) << 8) + int(rest[current+1])
		current += 2

		extensionDataLength := (int(rest[current]) << 8) + int(rest[current+1])
		current += 2

		if extensionType == 0 {
			// Skip over number of names as we're assuming there's just one
			current += 2

			nameType := rest[current]
			current += 1
			if nameType != 0 {
				log.Printf("Not a hostname")
				return
			}
			nameLen := (int(rest[current]) << 8) + int(rest[current+1])
			current += 2
			hostname = string(rest[current : current+nameLen])
		}

		current += extensionDataLength
	}

	if hostname == "" {
		log.Printf("No hostname")
		return
	}
	bodydata = append(firstByte, versionBytes...)
	bodydata = append(bodydata, restLengthBytes...)
	bodydata = append(bodydata, rest...)
	return hostname, bodydata
}
