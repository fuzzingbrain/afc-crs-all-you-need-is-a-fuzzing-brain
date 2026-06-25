#!/usr/bin/env python3
import base64
from pymongo import MongoClient
from datetime import datetime

client = MongoClient()
db = client['fuzzingbrain']

start = datetime(2026, 1, 24, 22, 48)
end = datetime(2026, 1, 24, 22, 55)

povs = list(db.povs.find({'created_at': {'$gte': start, '$lt': end}}).sort('created_at', 1).limit(3))
print(f'Found {len(povs)} POVs')

for i, pov in enumerate(povs):
    blob = base64.b64decode(pov['blob'])
    print(f'\n=== POV {i+1} (attempt={pov.get("attempt")}) ===')
    print(f'Size: {len(blob)} bytes')

    # Profile class at offset 12
    pclass = blob[12:16] if len(blob) > 16 else b''
    print(f'Profile Class (0x0C): {pclass}')

    # Color space at offset 16
    cs = blob[16:20] if len(blob) > 20 else b''
    print(f'Color Space (0x10): {cs}')

    # PCS at offset 20
    pcs = blob[20:24] if len(blob) > 24 else b''
    print(f'PCS (0x14): {pcs}')

    # Signature at offset 36
    sig = blob[36:40] if len(blob) > 40 else b''
    print(f'Signature (0x24): {sig}')

    # Tag count at offset 128
    if len(blob) >= 132:
        tag_count = int.from_bytes(blob[128:132], 'big')
        print(f'Tag count: {tag_count}')

        # Parse tag table
        offset = 132
        for j in range(min(tag_count, 10)):
            if offset + 12 > len(blob):
                break
            tag_sig = blob[offset:offset+4]
            tag_off = int.from_bytes(blob[offset+4:offset+8], 'big')
            tag_size = int.from_bytes(blob[offset+8:offset+12], 'big')
            print(f'  Tag {j+1}: {tag_sig} @ offset={tag_off}, size={tag_size}')

            # 检查 A2B0 tag 的数据类型
            if tag_sig == b'A2B0' and tag_off < len(blob):
                tag_data = blob[tag_off:min(tag_off+tag_size, len(blob))]
                print(f'    A2B0 tag type: {tag_data[:4]}')
                if len(tag_data) >= 32 and tag_data[:4] == b'mAB ':
                    # mAB structure:
                    # 0-3: 'mAB '
                    # 4-7: reserved
                    # 8: input channels
                    # 9: output channels
                    # 10-11: padding
                    # 12-15: B curves offset
                    # 16-19: Matrix offset
                    # 20-23: M curves offset
                    # 24-27: CLUT offset
                    # 28-31: A curves offset
                    in_ch = tag_data[8]
                    out_ch = tag_data[9]
                    b_off = int.from_bytes(tag_data[12:16], 'big')
                    mat_off = int.from_bytes(tag_data[16:20], 'big')
                    m_off = int.from_bytes(tag_data[20:24], 'big')
                    clut_off = int.from_bytes(tag_data[24:28], 'big')
                    a_off = int.from_bytes(tag_data[28:32], 'big')
                    print(f'    Input/Output channels: {in_ch}/{out_ch}')
                    print(f'    B curves offset: {b_off}')
                    print(f'    Matrix offset: {mat_off}')
                    print(f'    M curves offset: {m_off}')
                    print(f'    CLUT offset: {clut_off}')
                    print(f'    A curves offset: {a_off}')
                    print(f'    Full mAB data hex: {tag_data.hex()}')

            offset += 12
    else:
        print('Profile too small for tag table')

    # Hex dump first 160 bytes
    print('\nHex dump (first 160 bytes):')
    for row in range(0, min(160, len(blob)), 16):
        hex_part = ' '.join(f'{b:02x}' for b in blob[row:row+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in blob[row:row+16])
        print(f'  {row:04x}: {hex_part:<48} {ascii_part}')
