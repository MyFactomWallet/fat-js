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
        if (builder instanceof TransactionEntryBuilder) {
            
            let content = {}
            
	    content.version = 1;
            content.transactions = this._transactions;
		
            const unixSeconds = Math.round(new Date().getTime() / 1000);
            this._timestamp = unixSeconds;

            this._extIds = [unixSeconds.toString()];

            this._tokenChainId = builder._tokenChainId;
            let i = 0;
            for ( i = 0 ; i < content.transactions.length; ++i ) {
                this._extIds.push(content.transactions[i].getRCD());
                this._extIds.push(content.transactions[i].getSignature());
            }
            
        } else { //from object
            if (!builder.data.transactions) throw new Error("Valid FAT-2 transactions must be included");
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
    getTransaction(index) {
        return this.transactions[index];
    }

    /**
     * Get the factom-js Entry object representing the signed FAT transaction. Can be submitted directly to Factom
     * @method
     * @see https://github.com/PaulBernier/factomjs/blob/master/src/entry.js
     * @returns {Entry} - Get the Factom-JS Factom entry representation of the transaction, including extids & other signatures
     * @example
     * const {FactomCli, Entry, Chain} = require('factom');
     const cli = new FactomCli(); // Default factomd connection to localhost:8088 and walletd connection to localhost:8089

     const tx = new TransactionBuilder()
     .input("pFCT", "Fs1q7FHcW4Ti9tngdGAbA3CxMjhyXtNyB1BSdc8uR46jVUVCWtbJ", 150)
     .convert("PEG")
     .build();

     //"cast" the entry object to prevent compatibility issues
     const entry = Entry.builder(tx.getEntry()).build();

     await cli.add(entry, "Es32PjobTxPTd73dohEFRegMFRLv3X5WZ4FXEwNN8kE2pMDfeMym"); //commit the transaction entry to the token chain
     */
    getEntry() {
        if (!this._tokenChainId) throw new Error('Can only get a valid Factom entry for a transaction built using TransactionBuilder');

        return Entry.builder()
            .chainId(this._tokenChainId)
            .extIds(this._extIds, 'utf8')
            .content(this._content, 'utf8')
            .build();
    }

    /**
     * Get the token chain ID for this transaction
     * @method
     * @returns {string} - The chain ID of the pegnet 
     */
    getChainId() {
        return this._tokenChainId;
    }

    /**
     * Get the Factom entryhash of the transaction.
     * @method
     * @returns {string} - The entryhash of the transaction. Only defined if the Transaction was constructed from an object
     */
    getEntryhash() {
        return this._entryhash;
    }

    /**
     * Get the unix timestamp of when the Transaction was signed (locally built transactions) or committed to Factom (from RPC response JSON)
     * @method
     * @returns {number} - The integer unix timestamp
     */
    getTimestamp() {
        return this._timestamp;
    }

    /**
     * Get the pending status of the transaction at the time of request.
     * @method
     * @returns {boolean} - The pending status of the entry in the daemon
     */
    getPending() {
        return this._pending || false;
    }

    /**
     * Validate all the signatures in the transaction against the input addresses
     * @method
     * @returns {boolean} returns true if signatures are valid, throws error otherwise.
     */
    validateSignatures() {
        if ( this._signature === undefined || this._rcd === undefined ) {
            throw new Error("Transaction not signed")
        }
        
        if( !nacl.detached.verify(fctUtil.sha512(this.getMarshalDataSig(0)), this._signature[0], Buffer.from(this._rcd, 1).slice(1)) ) {
            throw new Error("Invalid Transaction Signature for input " + i.toString())
        }
        
        return true;
    }
}

module.exports = Transaction;
