// Usage and Testing
1. **Build**
   ```
   make
   ```
   This compiles the eBPF object, generates the skeleton, and builds the user-space binary `write_counter_user`.

2. **Run (requires root)**
   ```
   sudo ./write_counter_user
   ```
   It will print a header and then update every second:
   ```
     writes/s      bytes/s
          123         45678
   ```

3. **Generate sys_write activity to test**
   - Simple loop (many small writes):
     ```
     while true; do echo "hello" > /tmp/testfile; done
     ```
   You should immediately see non-zero `writes/s` and growing `bytes/s` corresponding to the requested write sizes.

4. **What the numbers mean**
   - `writes/s`: number of times the `write()` system call was entered per second.
   - `bytes/s`: total requested bytes per second (the `count` parameter passed to `write()`).
   - Note: this only traces the classic `sys_write` (not `writev`, `pwrite`, etc.). It counts requested bytes on entry (not actual bytes returned on success — that would require a more complex entry+exit pairing).
