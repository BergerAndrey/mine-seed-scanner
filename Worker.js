const encoder = new TextEncoder();
const keyCache = new Map();

async function getHmacKey(serverSeed) {
    if (keyCache.has(serverSeed)) return keyCache.get(serverSeed);
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(serverSeed),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    keyCache.set(serverSeed, key);
    return key;
}

async function hmacSha256Bytes(serverSeed, message) {
    const key = await getHmacKey(serverSeed);
    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
    return new Uint8Array(signature);
}

async function getMinePositions(serverSeed, clientSeed, nonce, mineCount) {
    const positions = [...Array(25).keys()];
    const mines = [];
    let allBytes = new Uint8Array(0);
    let round = 0;

    while (allBytes.length < mineCount * 4) {
        const msg = clientSeed + ':' + nonce + ':' + round;
        const digest = await hmacSha256Bytes(serverSeed, msg);
        const merged = new Uint8Array(allBytes.length + digest.length);
        merged.set(allBytes, 0);
        merged.set(digest, allBytes.length);
        allBytes = merged;
        round++;
    }

    for (let i = 0; i < mineCount; i++) {
        const offset = i * 4;
        const valInt =
            (allBytes[offset] * 16777216) +
            (allBytes[offset + 1] * 65536) +
            (allBytes[offset + 2] * 256) +
            allBytes[offset + 3];
        const val = valInt / 4294967296;
        const idx = Math.floor(val * positions.length);
        mines.push(positions.splice(idx, 1)[0]);
    }

    return mines;
}

self.onmessage = async function (e) {
    const data = e.data;
    let processed = 0;
    const total = data.endNonce - data.startNonce;

    for (let nonce = data.startNonce; nonce < data.endNonce; nonce++) {
        const mines = await getMinePositions(
            data.serverSeed,
            data.clientSeed,
            nonce,
            data.mineCount
        );

        const mineSet = new Set(mines);
        const diamonds = data.diamondPositions.filter(p => !mineSet.has(p));

        if (diamonds.length === data.diamondPositions.length) {
            self.postMessage({ found: true, nonce: nonce, mines: mines });
        }

        processed++;
        if (processed % 250 === 0 || processed === total) {
            self.postMessage({
                progress: (processed / total * 100).toFixed(1)
            });
        }
    }

    self.postMessage({ done: true });
};
