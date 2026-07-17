const crypto = require("crypto");
const { encrypt } = require("./encryption");

class AirpayClient {

    /**
     * @type {AirpayClient}
     */
    static instance;

    /**
     * @private
     * @param {Object} config
     */
    constructor(config) {
        this.config = config;
    }

    /**
     * Initializes the singleton.
     * Call once during application startup.
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
     * Returns the singleton instance.
     *
     * @returns {AirpayClient}
     */
    static getInstance() {

        if (!AirpayClient.instance) {
            throw new Error(
                "AirpayClient has not been initialized. Call AirpayClient.initialize() first."
            );
        }

        return AirpayClient.instance;
    }

    /**
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
     * @param {Object} payload
     * @returns {string}
     */
    generateChecksum(payload) {
        const text = Object.keys(payload)
            .sort()
            .map(key => payload[key] ?? "")
            .join("");

        return crypto
            .createHash("sha256")
            .update(text)
            .digest("hex");
    }

    /**
     * @param {Object} payload
     * @returns {Object}
     */
    createPaymentRequest(payload) {

        return {
            paymentUrl: this.config.paymentUrl,
            merchant_id: this.config.merchantId,
            privatekey: this.generatePrivateKey(),
            checksum: this.generateChecksum(payload),
            encdata: this.encryptPayload(payload),
        };

    }
}

module.exports = AirpayClient;
