"""
Offsets updated for Version: 2026.01.17-4b0f30090
"""

import keyboard
from memory import EvasiveProcess, get_pid_by_name

import time

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008

desired_access = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
pid = get_pid_by_name("HytaleClient.exe")
process = EvasiveProcess(pid, desired_access)

# Fetched with Cheat Enginge Pointerscan.
# I assume before 0xA7, its the pointer to the player struct or something of the sort
base_offset = 0x027C7170
offsets = [0x50, 0x70, 0x38, 0x120, 0x18, 0xA7]

def resolve_pointer_chain(proc, base_addr, offsets):
    addr = proc.read_long(base_addr)
    for offset in offsets[:-1]:
        addr = proc.read_long(addr + offset)
        if addr == 0:
            return 0
    return addr + offsets[-1]

while True:
    try:
        if keyboard.is_pressed('f'):
            base_address = process.base + base_offset
            target_address = resolve_pointer_chain(process, base_address, offsets)
            
            if target_address == 0:
                continue

            current_val_bytes = process.read(target_address, 1)
            
            if current_val_bytes is None:
                continue

            current_val = int.from_bytes(current_val_bytes, 'little')
            new_val = 0 if current_val == 1 else 1
            process.write(target_address, bytes([new_val]))

            time.sleep(0.1)
    except Exception as e:
        print(f"Error: {e}")
        break
