package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

func main() {
	preferredMTU := 1500
	wg := Wireguard{}
	tun, tnet, err := wg.GenerateTUN(
		[]netip.Addr{netip.MustParseAddr("10.0.0.3")},
		[]netip.Addr{netip.MustParseAddr("1.1.1.1")},
		&preferredMTU)
	if err != nil {
		log.Panic("Failed to create TUN device:", err)
	}

	dev, err := wg.CreateDevice(tun, device.LogLevelVerbose)
	if err != nil {
		log.Panic("Failed to create WireGuard device")
	}

	err = dev.IpcSet(fmt.Sprintf(`private_key=%s
public_key=%s
allowed_ip=0.0.0.0/0
endpoint=<YOUR_VM_IP>:51820
`, base64ToHex(""), base64ToHex("")))

	if err != nil {
		log.Panic("Failed to set WireGuard configuration:", err)
	}

	err = dev.Up()
	if err != nil {
		log.Panic("Failed to bring up WireGuard device:", err)
	}

	fmt.Println("Connected to WireGuard server")

	client := http.Client{
		Transport: &http.Transport{
			DialContext:     tnet.DialContext,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get("https://api.ipify.org?format=json")
	if err != nil {
		log.Panic(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Panic(err)
	}
	fmt.Printf("Connected to remote host! Using IP address for proxy: %s\n", string(body))

	handler := &proxy{
		Tunnel: tnet,
	}

	log.Println("Starting proxy server on", "127.0.0.1:8080")
	if err := http.ListenAndServe("127.0.0.1:8080", handler); err != nil {
		log.Fatal("ListenAndServe:", err)
	}

}

func base64ToHex(base64Key string) string {
	decodedKey, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		log.Panic("Failed to decode base64 key:", err)
	}
	hexKey := hex.EncodeToString(decodedKey)
	return hexKey
}
