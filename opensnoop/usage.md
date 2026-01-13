//Usage and Testing
1. **Build**
   ```bash
   make
   ```
   This produces `opensnoop_user` and the skeleton header.

2. **Run (must be root)**
   - Trace **all** processes:
     ```bash
     sudo ./opensnoop_user
     ```
   - Trace **only** a specific PID (replace 12345):
     ```bash
     sudo ./opensnoop_user 12345
     ```

3. **View output** (in another terminal):
   ```bash
   sudo cat /sys/kernel/debug/tracing/trace_pipe
   ```
   You will see lines like:
   ```
   OPEN PID=1234 COMM=bash FILE=/etc/passwd
   OPEN PID=5678 COMM=cat FILE=/home/user/test.txt
   ```
   - The line appears on every open/openat attempt (success or failure).
   - If you specified a PID, only lines from that PID will appear.

4. **Testing**
   - Start the tool without a PID argument (traces everything).
   - In any shell, run commands that open files:
     ```bash
     cat /etc/passwd
     touch /tmp/testfile
     ls -l /proc
     ```
   - You should immediately see corresponding OPEN lines in `trace_pipe`.
   - To test filtering: find a shell's PID (`echo $$`), run `sudo ./opensnoop_user <that_pid>`, then in **that same shell only** run file-opening commands. No events from other processes will appear.

5. **Stopping**
   - Ctrl+C in the opensnoop_user terminal → it automatically detaches and cleans up.
   - If it gets stuck for any reason, manually clear trace buffer:
     ```bash
     sudo sh -c "echo > /sys/kernel/debug/tracing/trace"
     ```
