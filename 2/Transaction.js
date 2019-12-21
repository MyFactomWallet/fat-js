const constant = require('../constant');
const nacl = require('tweetnacl/nacl-fast').sign;
const {Entry} = require('factom');
const fctUtil = require('factom/src/util');
const fctIdentityCrypto = require('factom-identity-lib/src/crypto');
const TransactionBuilder = require('./TransactionBuilder');
const JSONBig = require('json-bigint')({strict: true});
const BigNumber = require('bignumber.js');

/**
 * Model A signed or unsigned FAT-0 Transaction
 * @alias Transaction0
 * @protected
 * @class
 * @example
 * //From transaction builder
 * let tx = new TransactionBuilder(tokenChainId)
 * .input("Fs1q7FHcW4Ti9tngdGAbA3CxMjhyXtNyB1BSdc8uR46jVUVCWtbJ", 150)
 * .output("FA3aECpw3gEZ7CMQvRNxEtKBGKAos3922oqYLcHQ9NqXHudC6YBM", 150)
 * .build();
 *
 * tx.getInputs(); // => {"FA1PkAEbmo1XNangSnxmKqi1PN5sVDbQ6zsnXCsMUejT66WaDgkm":150}
 *
 * tx.getChainId(); // => "013de826902b7d075f00101649ca4fa7b49b5157cba736b2ca90f67e2ad6e8ec"
 *
 *
 * //or from API response
 * const response =
 * {
 *     entryhash: '68f3ca3a8c9f7a0cb32dc9717347cb179b63096e051a60ce8be9c292d29795af',
 *     timestamp: 1550696040,
 *     data:
 *         {
 *             inputs: {FA1zT4aFpEvcnPqPCigB3fvGu4Q4mTXY22iiuV69DqE1pNhdF2MC: 10},
 *             outputs: {FA3aECpw3gEZ7CMQvRNxEtKBGKAos3922oqYLcHQ9NqXHudC6YBM: 10}
 *         }
 * };
 *
 * tx = new Transaction(response);
 *
 * tx.getEntryHash(); // => "68f3ca3a8c9f7a0cb32dc9717347cb179b63096e051a60ce8be9c292d29795af"
 */
class Transaction {

    /**
     * @constructor
     * @param {(TransactionBuilder|object)} builder - Either a TransactionBuilder object or a FAT-0 transaction object content
     */
    constructor(builder) {
        if (builder instanceof TransactionBuilder) {
            this._input = builder._input;
            		
            if ( builder._conversion !== undefined ) {
                this._conversion = builder._conversion;
            }

            if ( builder._transfers.length > 0 ) {
                this._transfers = builder._transfers;
            }

            if ( builder._metadata !== undefined ) {
                this._metadata = builder._metadata;
            }

            this._key = builder._key;
            this._rcd = Buffer.concat([constant.RCD_TYPE_1, Buffer.from(builder._key.publicKey)]);
            
        } else { //from object
            if (!builder.data.input) throw new Error("Valid FAT-2 transactions must include input");
            if (!builder.data.conversion) throw new Error("Valid FAT-2 transactions must include conversion");
            if (!builder.data.transfers) throw new Error("Valid FAT-2 transactions must include transaction");
            this._input = builder.data.input;
            this._transfers = builder.data.transfers;
            this._conversion = builder.data.conversion;

            this._metadata = builder.data.metadata;

            this._entryhash = builder.entryhash;
            this._timestamp = builder.timestamp;
            this._pending = builder.pending;
        }

        Object.freeze(this);
    }

    /**
     * Get the inputs address for the transaction 
     * @method
     * @returns {string} - The transaction input address
     */
    getInput() {
        return this._input;
    }

    /**
     * Get the outputs address for the transaction 
     * @method
     * @returns {string|undefined} - The transaction's output address
     */
    getConversion() {
        return this._conversion;
    }
    
    /**
     * Returns a buffer of the RCD 
     * @method
     * @returns {Buffer} - The rcd associated with the input address
     */
    getRCD() {
        return this._rcd;
    }
    
    /**
     * Get the output asset to convert into 
     * @method
     * @returns { [{string,number}] | undefined } - The transaction's asset array of transfers
     */
    getTransfers() {
        return this._transfers;
    }

    /**
     * Get the metadata if present for the transaction if present
     * @method
     * @returns {*} - The transaction's metadata (if present, undefined if not)
     */
    getMetadata() {
        return this._metadata;
    }

    sign(hashed) {
        let signature = undefined
        if ( this._key.secretKey !== undefined ) {
             signature = nacl.detached(hashed, this._key.secretKey);
        } 
        return signature
    }
    /**
     * Validate all the signatures in the transaction against the input addresses
     * @method
     * @returns {boolean} returns true if signatures are valid, throws error otherwise.
     */
    validateSignature(hashed, signature) {
        if ( signature === undefined || this._rcd === undefined ) {
            throw new Error("Transaction not signed")
        }
        
        if( !nacl.detached.verify(hashed, signature, Buffer.from(this._rcd, 1).slice(1)) ) {
            return false;
        }
        
        return true;
    }
}


module.exports = Transaction;
