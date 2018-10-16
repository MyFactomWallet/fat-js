const crypto = require('crypto');
const util = require('../util');
const factomCryptoValidation = require('factom-identity-lib/src/validation');
const fctIdentityCrypto = require('factom-identity-lib/src/crypto');
const fctIdentityUtil = require('factom-identity-lib/src/validation');
const Transaction = require('./Transaction').Transaction;


class IssuanceBuilder {

    constructor(rootChainId, tokenId, sk1) {
        if (!fctIdentityUtil.isValidIdentityChainId(rootChainId)) throw new Error("You must include a valid issuer identity Root Chain Id to issue a FAT token");
        this._rootChainId = rootChainId;

        if (tokenId === undefined || typeof  tokenId !== 'string') throw new Error('Token is a required string');
        this._tokenId = tokenId;

        if (!factomCryptoValidation.isValidSk1(sk1)) throw new Error("Supplied key is not a valid sk1 private key");
        this._sk1 = sk1;

        this._type = 'FAT-0'
    }

    name(name) {
        if (!name) throw new Error("Token name must be defined");
        this._name = name;
        return this;
    };

    symbol(symbol) {
        if (!symbol) throw new Error("Token symbol must be defined");
        if (!new RegExp('[A-Z ]+').test(symbol)) throw new Error("Token symbol must only contain capital letters A-Z");
        if (symbol.length == 0 || symbol.length > 4) throw new Error("Token symbol must be 1 - 4 characters");
        this._symbol = symbol;
        return this;
    };

    supply(supply) {
        if (isNaN(supply)) throw new Error("Supply must be a number");
        if (supply <= 0) throw new Error("Supply must be > 0");
        this._supply = supply;
        return this;
    };

    salt(salt) {
        if (typeof salt !== 'string' || salt.length < 1) throw new Error('salt must be a non empty string, if defined (optional)');
        this._salt = salt;
        return this;
    }

    coinbase(transaction) {
        if (!transaction instanceof Transaction) throw new Error("Transaction must be of type Transaction");
        if (!this._transactions) this._transactions = [transaction];
        else this._transactions.push(transaction);
        return this;
    };

    build() {
        //validate required fields

        return new Issuance(this);
    }
}

class Issuance {
    constructor(builder) {

        if (builder instanceof IssuanceBuilder) {
            this._type = builder._type;
            this._name = builder._name;
            this._symbol = builder._symbol;
            this._supply = builder._supply;
            this._salt = builder._salt || crypto.randomBytes(32).toString('hex');

            this._content = JSON.stringify(this);

            this._tokenId = builder._tokenId;
            this._rootChainId = builder._rootChainId;

            this._transactions = builder._transactions || [];

            //handle issuance signing
            this._extIds = [fctIdentityCrypto.sign(builder._sk1, util.getTransactionChainId(builder._tokenId, builder._rootChainId) + this._content)];

        } else if (typeof builder === 'object') {
            this._type = builder.type;
            this._name = builder.name;
            this._symbol = builder.symbol;
            this._supply = builder._supply;
            this._salt = builder.salt;
            this._content = JSON.stringify(this);
            this._extIds = builder._extIds;
        }

        Object.freeze(this);
    }

    getTokenId() {
        return this._tokenId;
    }

    getRootChainId() {
        return this._rootChainId;
    }

    getTransactions() {
        return this._transactions;
    }

    getType() {
        return this._type;
    }

    getName() {
        return this._name;
    }

    getSymbol() {
        return this._symbol;
    }

    getSupply() {
        return this._supply;
    }

    getSalt() {
        return this._salt;
    }

    getContent() {
        return this._content;
    }

    getExtIds() {
        return this._extIds;
    }

    toObject() {
        return JSON.parse(this._content);
    }
}

module.exports = {
    IssuanceBuilder,
    Issuance
};