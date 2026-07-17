const crypto = require("crypto");

/**
 * Encrypt payload using AES-256-CBC.
 *
 * @param {string} plainText
 * @param {string} secretKey
 * @returns {string}
 */
function encrypt(plainText, secretKey) {

    const key = crypto
        .createHash("sha256")
        .update(secretKey)
        .digest();

    const iv = Buffer.alloc(16);

    const cipher = crypto.createCipheriv(
        "aes-256-cbc",
        key,
        iv
    );
    let encrypted = cipher.update(
        plainText,
        "utf8",
        "base64"
    );
    encrypted += cipher.final("base64");
    return encrypted;
}

module.exports = {
    encrypt
};
