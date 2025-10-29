import crypto from "crypto";
import fetch from "node-fetch";

const N8N_WEBHOOK = "https://cloneratriage.app.n8n.cloud/webhook/meta-flow"; // your existing webhook
const PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
PASTE_YOUR_PRIVATE_KEY_HERE
-----END RSA PRIVATE KEY-----`;

export default async function handler(req, res) {
  try {
    const { encrypted_flow_data, encrypted_aes_key, initial_vector } = req.body;

    // Step 1: decrypt AES key
    const aesKey = crypto.privateDecrypt(
      { key: PRIVATE_KEY, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
      Buffer.from(encrypted_aes_key, "base64")
    );

    // Step 2: decrypt request
    const iv = Buffer.from(initial_vector, "base64");
    const decipher = crypto.createDecipheriv("aes-128-cbc", aesKey, iv);
    let decrypted = decipher.update(Buffer.from(encrypted_flow_data, "base64"));
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    const padLen = decrypted[decrypted.length - 1];
    const jsonBody = JSON.parse(decrypted.slice(0, -padLen).toString("utf8"));

    console.log("Meta decrypted payload:", jsonBody);

    // Step 3: send to n8n for business logic
    const n8nResponse = await fetch(N8N_WEBHOOK, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(jsonBody)
    });

    const plainResult = await n8nResponse.json();

    // Step 4: re-encrypt for Meta
    const newIv = crypto.randomBytes(16);
    const respBytes = Buffer.from(JSON.stringify(plainResult));
    const padLen2 = 16 - (respBytes.length % 16);
    const paddedResp = Buffer.concat([respBytes, Buffer.alloc(padLen2, padLen2)]);

    const cipher = crypto.createCipheriv("aes-128-cbc", aesKey, newIv);
    let encrypted = cipher.update(paddedResp);
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    const response = {
      encrypted_flow_data: encrypted.toString("base64"),
      encrypted_aes_key,
      initial_vector: newIv.toString("base64")
    };

    res.status(200).json(response);
  } catch (err) {
    console.error("Error processing Meta flow:", err);
    res.status(421).json({ error: "Decryption or encryption failed" });
  }
}
