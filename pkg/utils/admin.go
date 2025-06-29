package utils

import "github.com/osrg/gobgp/v4/pkg/packet/bgp"

// Returns the binary formatted Administrative Shutdown Communication from the
// given string value.
func NewAdministrativeCommunication(communication string) (data []byte) {
	if communication == "" {
		return nil
	}
	com := []byte(communication)
	if len(com) > bgp.BGP_ERROR_ADMINISTRATIVE_COMMUNICATION_MAX {
		data = []byte{bgp.BGP_ERROR_ADMINISTRATIVE_COMMUNICATION_MAX}
		data = append(data, com[:bgp.BGP_ERROR_ADMINISTRATIVE_COMMUNICATION_MAX]...)
	} else {
		data = []byte{byte(len(com))}
		data = append(data, com...)
	}
	return data
}

// Parses the given NOTIFICATION message data as a binary value and returns
// the Administrative Shutdown Communication in string and the rest binary.
func DecodeAdministrativeCommunication(data []byte) (string, []byte) {
	if len(data) == 0 {
		return "", data
	}
	communicationLen := min(int(data[0]), bgp.BGP_ERROR_ADMINISTRATIVE_COMMUNICATION_MAX)
	communicationLen = min(communicationLen, len(data)-1)
	return string(data[1 : communicationLen+1]), data[communicationLen+1:]
}
