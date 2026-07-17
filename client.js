const axios = require("axios");
const crypto = require("node:crypto");
const { encrypt } = require("./encryption");

class AirpayClient {

    /**
     * @type {AirpayClient | null}
     */
    static instance = null;

    /**
     * @type {Promise<string> | null}
     */
    tokenPromise = null;

    /**
     * @private
     * @param {Object} config
     */
    constructor(config) {
        this.config = config;

        /**
         * @private
         * @type {string|null}
         */
        this.accessToken = null;

        /**
         * Epoch time in milliseconds.
         *
         * @private
         * @type {number}
         */
        this.tokenExpiresAt = 0;

        this.http = axios.create({
            timeout: 30000
        });
    }

    /**
     * Initialize singleton.
     *
     * @param {Object} config
     * @returns {AirpayClient}
     */
    static initialize(config) {

        if (!AirpayClient.instance) {
            AirpayClient.instance = new AirpayClient(config);
        }

        return AirpayClient.instance;

    }

    /**
     * Get singleton instance.
     *
     * @returns {AirpayClient}
     */
    static getInstance() {

        if (!AirpayClient.instance) {
            throw new Error(
                "AirpayClient is not initialized."
            );
        }

        return AirpayClient.instance;

    }

    /**
     * Returns a valid OAuth access token.
     *
     * Automatically refreshes when expired.
     *
     * @returns {Promise<string>}
     */
    async getAccessToken() {

        if (
            this.accessToken &&
            Date.now() < this.tokenExpiresAt
        ) {
            return this.accessToken;
        }

        if (this.tokenPromise) {
            return this.tokenPromise;
        }

        this.tokenPromise = this.refreshAccessToken();

        try {
            return await this.tokenPromise;
        } finally {
            this.tokenPromise = null;
        }

    }

    /**
     * Fetch a new OAuth token.
     *
     * @private
     * @returns {Promise<string>}
     */
    async refreshAccessToken() {

        const response = await this.http.post(
            this.config.oauthUrl,
            {
                client_id: this.config.clientId,
                client_secret: this.config.clientSecret,
                grant_type: "client_credentials"
            }
        );

        const data = response.data;
        this.accessToken = data.access_token;

        // Refresh one minute before expiry.
        this.tokenExpiresAt =
            Date.now() +
            ((data.expires_in - 60) * 1000);

        return this.accessToken;
    }

    /**
     * Generate private key.
     *
     * @returns {string}
     */
    generatePrivateKey() {

        return crypto
            .createHash("sha256")
            .update(
                `${this.config.secret}@${this.config.username}:|:${this.config.password}`
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

        return encrypt(
            JSON.stringify(payload),
            this.config.secretKey
        );
    }

    /**
     * Replace with official Airpay checksum algorithm.
     *
     * @param {Object} payload
     * @returns {string}
     */
    generateChecksum(payload) {

        const value = Object.keys(payload)
            .sort()
            .map(key => payload[key] ?? "")
            .join("");
        return crypto
            .createHash("sha256")
            .update(value)
            .digest("hex");

    }
    /**
     * Creates the request required by Airpay.
     *
     * @param {Object} payload
     * @returns {Promise<Object>}
     */
    async createPaymentRequest(payload) {

        const token = await this.getAccessToken();
        return {
            paymentUrl: `${this.config.paymentUrl}?token=${token}`,
            merchant_id: this.config.merchantId,
            privatekey: this.generatePrivateKey(),
            checksum: this.generateChecksum(payload),
            encdata: this.encryptPayload(payload)
        };

    }
    /**
     * Clears cached token.
     * Useful after authentication failures.
     */
    clearToken() {
        this.accessToken = null;
        this.tokenExpiresAt = 0;
    }
}

module.exports = AirpayClient;
