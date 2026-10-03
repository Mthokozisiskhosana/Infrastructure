// ============================================
// EXIF GPS READER
// Pulls the GPS coordinates a camera stored inside a JPEG photo
// (its EXIF metadata), so a report's location is where the photo was
// actually taken — not wherever the browser thinks the device is now.
//
// readExifGps(arrayBuffer) -> { lat, lng } or null
// Returns null for non-JPEGs, photos without GPS data, or corrupt data.
// ============================================

function readExifGps(buffer) {
    try {
        const view = new DataView(buffer);
        if (view.byteLength < 4 || view.getUint16(0) !== 0xFFD8) return null; // not a JPEG

        // Walk the JPEG segments looking for the APP1 "Exif" block.
        let offset = 2;
        while (offset + 4 <= view.byteLength) {
            const marker = view.getUint16(offset);
            if ((marker & 0xFF00) !== 0xFF00) return null;
            if (marker === 0xFFDA || marker === 0xFFD9) return null; // image data starts — no metadata after this

            const size = view.getUint16(offset + 2);
            const isExif = marker === 0xFFE1 &&
                size >= 16 &&
                view.getUint32(offset + 4) === 0x45786966 && // "Exif"
                view.getUint16(offset + 8) === 0x0000;

            if (isExif) {
                return readGpsFromTiff(view, offset + 10, Math.min(view.byteLength, offset + 2 + size));
            }
            offset += 2 + size;
        }
        return null;
    } catch (err) {
        return null; // malformed metadata — treat as "no location"
    }
}

function readGpsFromTiff(view, tiffStart, end) {
    const byteOrder = view.getUint16(tiffStart);
    const little = byteOrder === 0x4949;                 // "II" = Intel, little-endian
    if (!little && byteOrder !== 0x4D4D) return null;    // "MM" = Motorola, big-endian

    const inRange = (pos, len) => pos >= tiffStart && pos + len <= end;
    const u16 = pos => { if (!inRange(pos, 2)) throw new RangeError(); return view.getUint16(pos, little); };
    const u32 = pos => { if (!inRange(pos, 4)) throw new RangeError(); return view.getUint32(pos, little); };

    if (u16(tiffStart + 2) !== 42) return null;

    // Finds a tag's 12-byte entry in an IFD (a directory of tags).
    function findEntry(ifdStart, tag) {
        const count = u16(ifdStart);
        for (let i = 0; i < count; i++) {
            const entry = ifdStart + 2 + i * 12;
            if (u16(entry) === tag) return entry;
        }
        return null;
    }

    const ifd0 = tiffStart + u32(tiffStart + 4);
    const gpsPointer = findEntry(ifd0, 0x8825);          // GPSInfo IFD pointer
    if (gpsPointer === null) return null;
    const gpsIfd = tiffStart + u32(gpsPointer + 8);

    // Degrees/minutes/seconds stored as three RATIONALs (numerator/denominator pairs).
    function readDms(entry) {
        const valuesAt = tiffStart + u32(entry + 8);
        const parts = [];
        for (let i = 0; i < 3; i++) {
            const num = u32(valuesAt + i * 8);
            const den = u32(valuesAt + i * 8 + 4);
            if (den === 0) return NaN;
            parts.push(num / den);
        }
        return parts[0] + parts[1] / 60 + parts[2] / 3600;
    }

    const latRefEntry = findEntry(gpsIfd, 0x0001);
    const latEntry    = findEntry(gpsIfd, 0x0002);
    const lngRefEntry = findEntry(gpsIfd, 0x0003);
    const lngEntry    = findEntry(gpsIfd, 0x0004);
    if (latEntry === null || lngEntry === null) return null;

    let lat = readDms(latEntry);
    let lng = readDms(lngEntry);

    // N/S and E/W are single ASCII characters stored inline in the entry.
    if (latRefEntry !== null && String.fromCharCode(view.getUint8(latRefEntry + 8)) === 'S') lat = -lat;
    if (lngRefEntry !== null && String.fromCharCode(view.getUint8(lngRefEntry + 8)) === 'W') lng = -lng;

    if (!Number.isFinite(lat) || !Number.isFinite(lng)) return null;
    if (Math.abs(lat) > 90 || Math.abs(lng) > 180) return null;
    if (lat === 0 && lng === 0) return null;             // some cameras write 0,0 when they had no GPS fix

    return { lat, lng };
}

// Allow the parser to be tested from Node as well as used in the browser.
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { readExifGps };
}
