//Usage and Testing
1. **Build**
   Run `make all`. It will compile the eBPF object, generate the skeleton, and build the user-space binary `xdp_counter_user`.

2. **Testing with no real traffic**
   Create a veth pair:
   ```
   sudo ip link add veth0 type veth peer name veth1
   sudo ip addr add 10.10.20.1/24 dev veth0
   sudo ip addr add 10.10.20.2/24 dev veth1
   sudo ip link set veth0 up
   sudo ip link set veth1 up
   ```
   Attach the counter to one side:
   `sudo ./xdp_counter_user veth1`
   Generate traffic from the other side:
   `ping -I veth0 10.10.20.2`
   You should see non-zero pkt/s and bit/s.

3. **Run**
   Run as root on the interface you want to monitor:
   `sudo ./xdp_counter_user <interface>`
   Example: `sudo ./xdp_counter_user eth0` or `sudo ./xdp_counter_user veth1`

4. **What you will see**
   After attach, it prints a header and then every second:
   ```
      pkt/s        bit/s
       1234      9876543
   ```
   - `pkt/s` = packets per second (ingress on that interface)
   - `bit/s` = bits per second (Layer 2, including Ethernet headers)

5. **Stopping**
   Press Ctrl+C. The program automatically detaches the XDP program before exiting.
   If something goes wrong and it stays attached, manually remove with:
   `sudo ip link set <interface> xdp off`
