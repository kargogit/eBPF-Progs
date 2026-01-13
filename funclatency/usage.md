// Usage and Testing
1. **Build the program**
   Run `make`. This compiles the eBPF kernel object, generates the skeleton, and builds the user-space binary `funclatency_user`.

2. **Run the program (requires root)**
   ```
   sudo ./funclatency_user <kernel_function_name>
   ```
   - Good functions to start with:
     - `vfs_read` → measures time spent in file reads.
     - `__x64_sys_nanosleep` → measures time spent in the nanosleep syscall (easy to trigger).
   - The program will attach both a kprobe (entry) and kretprobe (exit) to the specified function.

3. **Generate activity to trigger the function**
   - For `__x64_sys_nanosleep`:
     In another terminal, run `sleep 1`, `sleep 0.5`, or a loop like `while true; do sleep 0.1; done`.
     You should see latencies clustered around the requested sleep time (e.g., ~1000000 µs for `sleep 1`).
   - For `vfs_read`:
     Run `find /usr -type f -exec cat {} + > /dev/null`.
     Latencies will vary depending on caching/disk speed (usually small if cached, larger on real I/O).

4. **What to look for in the output**
   - Every 5 seconds the program prints a histogram of observed latencies in microseconds.
   - Columns:
     - `usecs range`: Bucket range (0 → <1 µs, then 1→1, 2→3, 4→7, etc.).
     - `count`: Number of function executions in that bucket.
     - Bar of `*`: Visual proportion of counts in each bucket.
   - `Total calls`: Cumulative number of times the function returned.
   - The histogram accumulates over time (so totals grow as you generate more activity).
   - If you see no output besides "No calls observed yet", the function isn't being hit — try a different trigger or function.
   - Note: This measures wall-clock time from function entry to any exit. Nested calls to the same function (rare) may overwrite the start timestamp. For most functions this works perfectly.
