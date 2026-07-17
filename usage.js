/**
 * @typedef {Object} PaymentRequest
 * @property {string} orderId
 * @property {number} amount
 * @property {string} currency
 * @property {Object} buyer
 * @property {string} buyer.firstName
 * @property {string} buyer.lastName
 * @property {string} buyer.email
 * @property {string} buyer.phone
 */

class InitiatePaymentService {

    /**
     * @param {import("./client").AirpayClient} airpayClient
     */
    constructor(airpayClient) {
        this.airpay = airpayClient;
    }

    /**
     * Create Airpay payment request.
     *
     * @param {PaymentRequest} request
     */
    async execute(request) {

        const payload = {
            orderid: request.orderId,
            amount: request.amount.toFixed(2),
            currency_code: "356",
            iso_currency: request.currency,
            buyer_email: request.buyer.email,
            buyer_phone: request.buyer.phone,
            buyer_firstname: request.buyer.firstName,
            buyer_lastname: request.buyer.lastName
        };

        return this.airpay.createPaymentRequest(payload);

    }

}

module.exports = InitiatePaymentService;
