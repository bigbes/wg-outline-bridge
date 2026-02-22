package proxy

import (
	"bufio"
	"encoding/binary"
)

func PeekSNI(br *bufio.Reader) string {
	header, err := br.Peek(5)
	if err != nil {
		return ""
	}

	if header[0] != 0x16 {
		return ""
	}

	recordLength := int(binary.BigEndian.Uint16(header[3:5]))
	if recordLength == 0 {
		return ""
	}

	totalLength := min(5+recordLength, 16384+5)

	data, err := br.Peek(totalLength)
	if err != nil {
		return ""
	}

	return extractSNI(data[5:])
}

func extractSNI(handshake []byte) string {
	if len(handshake) < 1 {
		return ""
	}
	if handshake[0] != 0x01 {
		return ""
	}

	if len(handshake) < 4 {
		return ""
	}
	handshakeLength := uint32(handshake[1])<<16 | uint32(handshake[2])<<8 | uint32(handshake[3])
	handshake = handshake[4:]

	if uint32(len(handshake)) < handshakeLength {
		return ""
	}
	handshake = handshake[:handshakeLength]

	// Skip client version (2 bytes) + random (32 bytes)
	if len(handshake) < 34 {
		return ""
	}
	handshake = handshake[34:]

	// Skip session ID
	if len(handshake) < 1 {
		return ""
	}
	sessionIDLen := int(handshake[0])
	handshake = handshake[1:]
	if len(handshake) < sessionIDLen {
		return ""
	}
	handshake = handshake[sessionIDLen:]

	// Skip cipher suites
	if len(handshake) < 2 {
		return ""
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(handshake[:2]))
	handshake = handshake[2:]
	if len(handshake) < cipherSuitesLen {
		return ""
	}
	handshake = handshake[cipherSuitesLen:]

	// Skip compression methods
	if len(handshake) < 1 {
		return ""
	}
	compressionLen := int(handshake[0])
	handshake = handshake[1:]
	if len(handshake) < compressionLen {
		return ""
	}
	handshake = handshake[compressionLen:]

	// Extensions
	if len(handshake) < 2 {
		return ""
	}
	extensionsLen := int(binary.BigEndian.Uint16(handshake[:2]))
	handshake = handshake[2:]
	if len(handshake) < extensionsLen {
		return ""
	}
	extensions := handshake[:extensionsLen]

	for len(extensions) >= 4 {
		extType := binary.BigEndian.Uint16(extensions[:2])
		extLen := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4:]
		if len(extensions) < extLen {
			return ""
		}
		extData := extensions[:extLen]
		extensions = extensions[extLen:]

		if extType != 0x0000 {
			continue
		}

		// Parse server_name extension
		if len(extData) < 2 {
			return ""
		}
		listLen := int(binary.BigEndian.Uint16(extData[:2]))
		extData = extData[2:]
		if len(extData) < listLen {
			return ""
		}
		extData = extData[:listLen]

		for len(extData) >= 3 {
			nameType := extData[0]
			nameLen := int(binary.BigEndian.Uint16(extData[1:3]))
			extData = extData[3:]
			if len(extData) < nameLen {
				return ""
			}
			if nameType == 0 {
				return string(extData[:nameLen])
			}
			extData = extData[nameLen:]
		}
	}

	return ""
}
