# Test Data

## Converting PCAP to Binary sFlow Data

To extract raw sFlow data from a pcap file:

```bash
# Calculate offset: 24 (pcap header) + 14 (Ethernet) + 20 (IP) + 8 (UDP) = 66 bytes
# For sFlow v5, skip to where data starts with 0x00000005
dd if=sflow.pcap of=sflow.bin bs=1 skip=86 2>/dev/null
```

The offset (86 bytes) accounts for:
- 24 bytes: pcap global header
- 16 bytes: pcap packet header
- 14 bytes: Ethernet header
- 20 bytes: IP header
- 8 bytes: UDP header
- 4 bytes: alignment/padding

Verify the output starts with `00 00 00 05` (sFlow version 5):
```bash
hexdump -C sflow.bin | head -1
```
