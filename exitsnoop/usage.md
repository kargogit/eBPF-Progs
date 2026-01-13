//Usage and Testing
1. **Build**
   Run `make`. It generates `vmlinux.h` (needed for CO-RE access to `task_struct`), compiles the eBPF object, generates the skeleton, and builds `exitsnoop_user`.

2. **Run** (requires root)
   `sudo ./exitsnoop_user`
   It will print a startup message and wait.

3. **Generate events** (in another terminal)
   - Normal exit: `true` or `ls` → EXIT_CODE usually **0**
   - Non-zero exit: `false` → EXIT_CODE usually **1**
   - Signal termination: `sleep 100` then `Ctrl+C` → EXIT_CODE often **130** (SIGINT)
   - Kill: start a process (`sleep 100 &`) then `kill -9 <pid>` → EXIT_CODE usually **9** (SIGKILL)

4. **What to look for in output**
   Example lines:
   ```
   EXIT PID=12345 COMM=ls EXIT_CODE=0
   EXIT PID=12346 COMM=false EXIT_CODE=1
   EXIT PID=12347 COMM=sleep EXIT_CODE=130
   ```
   - **EXIT_CODE** is the raw kernel value passed to `do_exit()`.
     - **0–255**: Usually normal voluntary exit with that status (most programs use 0).
     - Positive non-zero values > 128 are often signal numbers (e.g., 130 = SIGINT, 137 = SIGKILL/9 + 128 offset in some contexts).
     - Exact interpretation matches what `wait(2)` would return (use `WIFEXITED`/`WEXITSTATUS` or `WIFSIGNALED`/`WTERMSIG` on the raw value).
