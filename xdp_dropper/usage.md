//Usage and Testing
A veth (Virtual Ethernet) pair acts like a physical cable between two interfaces. Sending a packet out of veth0 causes it to "arrive" as ingress on veth1, which will trigger the XDP hook.

1. Setup the pair:
sudo ip link add veth0 type veth peer name veth1
sudo ip addr add 10.10.20.1/24 dev veth0
sudo ip addr add 10.10.20.2/24 dev veth1
sudo ip link set veth0 up
sudo ip link set veth1 up


2. Attach your dropper to veth1:
sudo ./xdp_dropper_user veth1


3. Ping the peer:
ping -I veth0 10.10.20.2
