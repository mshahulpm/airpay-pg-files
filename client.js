const axios = require("axios");
const crypto = require("node:crypto");
const { encrypt } = require("./encryption");

class AirpayClient {

    constructor() {
        // load from environment variables
        this.config = {
            USERNAME: '',
            PASSWORD: '',
            SECRET: '',
            MERCHANT_ID: '',
            CLIENT_ID: '',
            CLIENT_SECRET: '',
            TOKEN_URL: '',
            URL: ''
        }
    }

    /**
     * Returns the Airpay encryption key
     *
     * @returns {string}
     */
    getEncryptionKey() {

        return crypto
            .createHash("md5")
            .update(
                `${this.config.USERNAME}~:~${this.config.PASSWORD}`
            )
            .digest("hex");

    }

    /**
     * Encrypt payload.
     *
     * @param {Object} payload
     * @returns {string}
     */
    encryptPayload(payload) {

        const key = this.getEncryptionKey();

        const iv = crypto.randomBytes(8).toString("hex");

        const cipher = crypto.createCipheriv(
            "aes-256-cbc",
            Buffer.from(key),
            Buffer.from(iv)
        );

        const raw = Buffer.concat([
            cipher.update(JSON.stringify(payload), "utf8"),
            cipher.final()
        ]);

        return iv + raw.toString("base64");

    }

    generatePrivateKey() {

        return crypto
            .createHash("sha256")
            .update(
                `${this.config.SECRET}@${this.config.USERNAME}:|:${this.config.PASSWORD}`
            )
            .digest("hex");
    }

    calculateChecksum(payload) {

        const sorted = Object.keys(payload)
            .sort()
            .reduce((obj, key) => {
                obj[key] = payload[key];
                return obj;
            }, {});

        const values = Object
            .values(sorted)
            .join("");

        const today = new Date()
            .toISOString()
            .split("T")[0];

        return crypto
            .createHash("sha256")
            .update(values + today)
            .digest("hex");

    }

    /**
     * Returns a valid Airpay OAuth token.
     *
     * @returns {Promise<string>}
     */
    async getToken() {

        // Return cached token if still valid.
        if (
            this.accessToken &&
            Date.now() < this.tokenExpiresAt
        ) {
            return this.accessToken;
        }

        // Another request is already refreshing the token.
        if (this.refreshPromise) {
            return this.refreshPromise;
        }

        this.refreshPromise = this.fetchToken();

        try {
            return await this.refreshPromise;
        } finally {
            this.refreshPromise = null;
        }

    }

    /**
     * Fetch a new OAuth access token.
     *
     * @private
     * @returns {Promise<string>}
     */
    async fetchToken() {

        const request = {
            client_id: this.config.CLIENT_ID,
            client_secret: this.config.CLIENT_SECRET,
            grant_type: "client_credentials",
            merchant_id: this.config.MERCHANT_ID
        };

        const response = await axios.post(
            this.config.TOKEN_URL,
            {
                merchant_id: this.config.MERCHANT_ID,
                encdata: this.encryptPayload(request),
                checksum: this.calculateCheckSum(request)
            }
        );

        const result = this.decryptPayload(
            response.data.response
        );

        if (result.status !== "success") {
            throw new Error(result.message);
        }

        this.accessToken = result.data.access_token;

        // Refresh 30 seconds before expiry.
        this.tokenExpiresAt =
            Date.now() +
            ((result.data.expires_in - 30) * 1000);

        return this.accessToken;

    }
    /**
     * Decrypts an Airpay encrypted response.
     *
     * Response format:
     * <16-char IV><Base64 Cipher Text>
     *
     * @param {string} encryptedPayload
     * @returns {Object}
     */
    decryptPayload(encryptedPayload) {

        const key = Buffer.from(
            this.getEncryptionKey(),
            "utf8"
        );

        // First 16 characters are the IV
        const iv = Buffer.from(
            encryptedPayload.substring(0, 16),
            "utf8"
        );

        // Remaining string is Base64 cipher text
        const cipherText = Buffer.from(
            encryptedPayload.substring(16),
            "base64"
        );

        const decipher = crypto.createDecipheriv(
            "aes-256-cbc",
            key,
            iv
        );

        const decrypted = Buffer.concat([
            decipher.update(cipherText),
            decipher.final()
        ]);

        return JSON.parse(
            decrypted.toString("utf8")
        );

    }

}

module.exports = AirpayClient;
