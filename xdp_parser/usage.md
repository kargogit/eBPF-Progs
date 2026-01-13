//Usage and Testing
1. **Build**
   Run `make all`. This compiles the eBPF object, generates the skeleton, and builds the user-space binary `xdp_parser_user`.

2. **Testing setup (recommended: use a veth pair to safely generate traffic)**
   ```bash
        # Create test interfaces
        sudo ip link add veth0 type veth peer name veth1
        sudo ip addr add 10.10.20.1/24 dev veth0
        sudo ip addr add 10.10.20.2/24 dev veth1
        sudo ip link set veth0 up
        sudo ip link set veth1 up
   ```

3. **Run the parser**
        # Attach parser with drop rule
        sudo ./xdp_parser_user veth1 10.10.20.2

4. **Confirm packets are actually arriving** (in another terminal)
   ```bash
        # Terminal 1: Watch veth1
        sudo tcpdump -i veth1 -n

        # Terminal 2: Generate traffic
        ping -I veth0 -c 5 10.10.20.2
   ```

5. **View output** (in yet another terminal)
   ```bash
        sudo ip netns add testns
        sudo ip link set veth0 netns testns
        sudo ip netns exec testns ip addr add 10.10.20.1/24 dev veth0
        sudo ip netns exec testns ip link set veth0 up
        sudo ip netns exec testns ping -I veth0 10.10.20.2  # Now this forces real TX
   ```

   We are not reading "/sys/kernel/debug/tracing/trace_pipe" through "sudo cat /sys/kernel/debug/tracing/trace_pipe" because kernel is optimizing away local-to-local veth traffic.
   When you ping an IP that the kernel considers local (including all veth interface IPs), it often never transmits the packet out the veth. Instead, it routes internally.
