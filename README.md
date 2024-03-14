# HTTP Proxying with Wireguard Tunnels in User Space

This is a very basic implementation of a user space Wireguard tunnel that can be used to proxy HTTP traffic through a Wireguard tunnel.

I talk a bit more about this on my [blog which you can read here](https://ryan-schachte.com/blog/userspace_wireguard_tunnels/).

# Run
`go run .` or `go build && ./lockbox`

I haven't optimized any of this, so if you want to test, modify the `<YOUR_VM_IP>` to be the IP of some VM you're using and make sure you add the private key of the client and public key of the server in this block:

```
err = dev.IpcSet(fmt.Sprintf(`private_key=%s
public_key=%s
allowed_ip=0.0.0.0/0
endpoint=<YOUR_VM_IP>:51820
`, base64ToHex(""), base64ToHex("")))
```

# Proxying

You can download a proxy switcher extension that points traffic in your browser to `localhost:8080` to push web traffic through the tunnel. Verify using something like `https://ipchicken.com`.