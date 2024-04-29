const crypto = require('crypto');

const TTL = 360;

const SHARED_SECRET = 'TEST1234';

async function generateTonProofPayload(req, res) {
    const payload = Buffer.alloc(48);
    crypto.randomFillSync(payload, 0, 8);

    const now = Math.floor(Date.now() / 1000);
    const ttl = TTL; // Assuming TTL is defined somewhere
    const expire = now + ttl;

    payload.writeBigUInt64BE(BigInt(expire), 8);

    const hmac = crypto.createHmac('sha256', Buffer.from(SHARED_SECRET, 'hex'));
    hmac.update(payload.subarray(0, 16));
    const signature = hmac.digest();

    signature.copy(payload, 16, 0, 32);

    const hex = payload.toString('hex');

    return res.status(200).send({
        status: true,
        message: "Payload Generated",
        payload: hex
    });
}

module.exports = {
    generateTonProofPayload
}

// Assuming TTL and SHARED_SECRET are defined somewhere

// generateTonProofPayload()
//     .then(payload => console.log(payload))
//     .catch(error => console.error(error));
