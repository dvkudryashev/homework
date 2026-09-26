package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

type EtherType uint16

const (
	IPv4 EtherType = 0x0800
	IPv6           = 0x86dd
	ARP            = 0x0806
)

const (
	FlagFIN uint8 = 1 << 0
	FlagSYN uint8 = 1 << 1
	FlagRST uint8 = 1 << 2
	FlagPSH uint8 = 1 << 3
	FlagACK uint8 = 1 << 4
	FlagURG uint8 = 1 << 5
)

func formatHex(hex []byte) string {
	var buffer []byte
	for i, b := range hex {
		if i == len(hex)-1 {
			buffer = fmt.Appendf(buffer, "%02x", b)
			break
		}
		buffer = fmt.Appendf(buffer, "%02x:", b)
	}
	return string(buffer)
}

func formatDec(dec []byte) string {
	var buffer []byte
	for i, b := range dec {
		if i == len(dec)-1 {
			buffer = fmt.Appendf(buffer, "%d", b)
			break
		}
		buffer = fmt.Appendf(buffer, "%d.", b)
	}
	return string(buffer)
}

func stringifyIPFlags(raw []byte) string {
	data := binary.BigEndian.Uint16(raw)

	var flags []string

	if data&(1<<14) != 0 {
		flags = append(flags, "DF")
	}

	if data&(1<<13) != 0 {
		flags = append(flags, "MF")
	}

	if len(flags) == 0 {
		return "none"
	}

	return strings.Join(flags, ",")
}

func parseIPOffset(raw []byte) uint16 {
	data := binary.BigEndian.Uint16(raw)
	return (data & 0x1fff) * 8
}

func stringifyTCPFlags(flags uint8) string {
	var result []string

	if flags&FlagFIN != 0 {
		result = append(result, "FIN")
	}

	if flags&FlagSYN != 0 {
		result = append(result, "SYN")
	}

	if flags&FlagRST != 0 {
		result = append(result, "RST")
	}

	if flags&FlagPSH != 0 {
		result = append(result, "PSH")
	}

	if flags&FlagACK != 0 {
		result = append(result, "ACK")
	}

	if flags&FlagURG != 0 {
		result = append(result, "URG")
	}

	if len(result) == 0 {
		return "none"
	}

	return strings.Join(result, ",")
}

func ipChecksumValid(header []byte) bool {
	storedChecksum := binary.BigEndian.Uint16(header[10:12])

	var sum uint32

	for i := 0; i < len(header); i += 2 {
		if i == 10 {
			continue
		}

		word := binary.BigEndian.Uint16(header[i : i+2])
		sum += uint32(word)
	}

	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	calculatedChecksum := ^uint16(sum)

	return calculatedChecksum == storedChecksum
}

func main() {
	// testData := `
	//001b213c4d5e 0025645d1e22 0800
	//4500003c1c464000400600000a000002 5db8d822
	//a86a0050 12345678 00000000 a002faf0 00000000
	//`

	scanner := bufio.NewScanner(os.Stdin)
	//scanner := bufio.NewScanner(strings.NewReader(testData))
	scanner.Split(bufio.ScanWords)

	var buffer []byte

	for scanner.Scan() {
		token := strings.ReplaceAll(scanner.Text(), ":", "")
		buffer = append(buffer, token...)
	}

	hexBuffer, err := hex.DecodeString(string(buffer))
	if err != nil {
		fmt.Printf("%s", err)
		return
	}

	dst := hexBuffer[0:6]
	src := hexBuffer[6:12]
	etherType := EtherType(binary.BigEndian.Uint16(hexBuffer[12:14]))

	fmt.Printf("eth.dst %s\n", formatHex(dst))
	fmt.Printf("eth.src %s\n", formatHex(src))
	fmt.Printf("eth.ethertype 0x%04x\n", etherType)

	if etherType == IPv4 {
		ipSlice := hexBuffer[14:]

		fmt.Printf("ip.version %d\n", ipSlice[0]>>4) // версия протокола

		ihlBytes := int((ipSlice[0] & 0x0f) * 4)

		fmt.Printf("ip.ihl_bytes %d\n", ihlBytes)                                 // длина заголовка в байтах
		fmt.Printf("ip.total_length %d\n", binary.BigEndian.Uint16(ipSlice[2:4])) // значение поля общей длины
		fmt.Printf("ip.id 0x%04x\n", binary.BigEndian.Uint16(ipSlice[4:6]))       // идентификатор в виде 0x1c46
		fmt.Printf("ip.flags %s\n", stringifyIPFlags(ipSlice[6:8]))               // DF, MF или none; при двух установленных — DF,MF
		fmt.Printf("ip.frag_offset %d\n", parseIPOffset(ipSlice[6:8]))            // смещение фрагмента в байтах
		fmt.Printf("ip.ttl %d\n", ipSlice[8])                                     // значение поля времени жизни

		ipProtocol := ipSlice[9]

		fmt.Printf("ip.protocol %d\n", ipProtocol) //номер протокола вышестоящего уровня
		fmt.Printf("ip.src %s\n", formatDec(ipSlice[12:16]))
		fmt.Printf("ip.dst %s\n", formatDec(ipSlice[16:20]))                      //адреса в десятично-точечной записи
		fmt.Printf("ip.checksum_valid %t\n", ipChecksumValid(ipSlice[:ihlBytes])) // true, если контрольная сумма заголовка сходится, иначе false

		ipTotalLength := int(binary.BigEndian.Uint16(ipSlice[2:4]))

		if ipProtocol == 6 {
			tcpSlice := ipSlice[ihlBytes:]

			fmt.Printf("tcp.src_port %d\n", binary.BigEndian.Uint16(tcpSlice[0:2]))
			fmt.Printf("tcp.dst_port %d\n", binary.BigEndian.Uint16(tcpSlice[2:4])) // номера портов
			fmt.Printf("tcp.seq %d\n", binary.BigEndian.Uint32(tcpSlice[4:8]))
			fmt.Printf("tcp.ack %d\n", binary.BigEndian.Uint32(tcpSlice[8:12])) // номер последовательности и номер подтверждения

			offsetBytes := int(tcpSlice[12]>>4) * 4

			fmt.Printf("tcp.data_offset_bytes %d\n", offsetBytes)                   // длина заголовка в байтах
			fmt.Printf("tcp.flags %s\n", stringifyTCPFlags(tcpSlice[13]))           // перечисление через запятую без пробелов в порядке FIN,SYN,RST,PSH,ACK,URG; при отсутствии установленных — none
			fmt.Printf("tcp.window %d\n", binary.BigEndian.Uint16(tcpSlice[14:16])) // размер окна

			payloadLength := ipTotalLength - ihlBytes - offsetBytes
			fmt.Printf("payload.length %d\n", payloadLength)
		}

		if ipProtocol == 17 {
			udpSlice := ipSlice[ihlBytes:]

			srcPort := binary.BigEndian.Uint16(udpSlice[0:2])
			dstPort := binary.BigEndian.Uint16(udpSlice[2:4])
			udpLength := binary.BigEndian.Uint16(udpSlice[4:6])

			fmt.Printf("udp.src_port %d\n", srcPort)
			fmt.Printf("udp.dst_port %d\n", dstPort)
			fmt.Printf("udp.length %d\n", udpLength)
			fmt.Printf("payload.length %d\n", udpLength-8)
		}
	}
}
