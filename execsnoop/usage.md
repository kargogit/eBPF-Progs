// Usage and Testing
1. Save the three files above (`execsnoop_kern.c`, `execsnoop_user.c`, `Makefile`).
2. Build:
   ```bash
   make
   ```
3. Run (requires root):
   ```bash
   sudo ./execsnoop_user
   ```
4. In another terminal, view live output:
   ```bash
   sudo cat /sys/kernel/debug/tracing/trace_pipe
   ```
5. Test by running any program:
   ```bash
   ls -l
   /bin/echo hello
   bash -c "echo test"
   ```
   You should see lines like:
   ```
   EXEC PID=12345 PPID=12340 UID=1000 COMM=bash FILE=/usr/bin/ls ARGS= ls -l
   ```
