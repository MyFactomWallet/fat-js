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
            
            let content = {}
            
            this._input = builder._input;
            
            content.input = this._input;
		
            if ( builder._conversion !== undefined ) {
                this._conversion = builder._conversion;
                content.conversion = this._conversion;
            }

            if ( builder._transfers.length > 0 ) {
                this._transfers = builder._transfers;
                content.transfers = this._transfers;
            }

            //this._output = builder._output;
            
            //content.output = this._output;
            //content.amount = this._amount;
            
            if ( builder._metadata !== undefined ) {
                this._metadata = builder._metadata;
                content.metadata = this._metadata;
            }

            this._content = JSONBig.stringify(content); //snapshot the tx object

		console.log(this._content)

            const unixSeconds = Math.round(new Date().getTime() / 1000);
            this._timestamp = unixSeconds;

            this._extIds = [unixSeconds.toString()];

            this._tokenChainId = builder._tokenChainId;

            if ( builder._signature !== undefined ) { //handle previously assembled transaction with added signatures

                this._rcd = Buffer.concat([constant.RCD_TYPE_1, builder._key.publicKey]);

                this._timestamp = builder._timestamp;
                this._signature = builder._signature;
                this._extIds = [this._timestamp.toString()];

                this._extIds.push(this._rcd);
                this._extIds.push(this._signature[0]);
            
            } else { //otherwise internally signed transaction
                let sigIndexCounter = 0;
                let valid = false;
                const index = Buffer.from(sigIndexCounter.toString());
                const timestamp = Buffer.from(unixSeconds.toString());
                const chainId = Buffer.from(builder._tokenChainId, 'hex');
                const content = Buffer.from(this._content);

                sigIndexCounter++;
                
                if ( builder._key.secretKey !== undefined ) {
                    this._signature = [nacl.detached(fctUtil.sha512(Buffer.concat([index, timestamp, chainId, content])), builder._key.secretKey)];
                    this._rcd = Buffer.concat([constant.RCD_TYPE_1, Buffer.from(builder._key.publicKey)]);
                    // if signatures aren't all valid then don't create external id's
                    this._extIds.push(this._rcd);
                    this._extIds.push(this._signature[0]);
                } else {
                    //need to store off key for signatures on second pass
                    this._key = builder._key;
                }
            }
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
    

    /**
     * Get the factom-js Entry object representing the signed FAT transaction. Can be submitted directly to Factom
     * @method
     * @see https://github.com/PaulBernier/factomjs/blob/master/src/entry.js
     * @returns {Entry} - Get the Factom-JS Factom entry representation of the transaction, including extids & other signatures
     * @example
     * const {FactomCli, Entry, Chain} = require('factom');
     const cli = new FactomCli(); // Default factomd connection to localhost:8088 and walletd connection to localhost:8089

     const tokenChainId = 'cffce0f409ebba4ed236d49d89c70e4bd1f1367d86402a3363366683265a242d';

     const tx = new TransactionBuilder(tokenChainId)
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
     * @returns {string} - The chain ID string. Undefined if the transaction is constructed from an object or unsigned
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
     * Get the assembled ("marshalled") data that needs to be signed for the transaction for the given input address index
     * @method
     * @param inputIndex {number} - The input index to marshal to prep for hashing then signing
     * @returns {Buffer} - Get the marshalled data that needs to be hashed then signed
     */
    getMarshalDataSig(inputIndex) {
        return getMarshalDataSig(this, inputIndex);
    }

    /**
     * Validate all the signatures in the transaction against the input addresses
     * @method
     * @returns {boolean} returns true if signatures are valid, throws error otherwise.
     */
    validateSignature() {
        if ( this._signature === undefined || this._rcd === undefined ) {
            throw new Error("Transaction not signed")
        }
        
        if( !nacl.detached.verify(fctUtil.sha512(this.getMarshalDataSig(0)), this._signature[0], Buffer.from(this._rcd, 1).slice(1)) ) {
            throw new Error("Invalid Transaction Signature for input " + i.toString())
        }
        
        return true;
    }
}

/**
 * Get the assembled ("marshalled") data that needs to be signed for the transaction for the given input address index
 * @method
 * @param tx {Transaction} - The transaction to get the marshalled data to sign from
 * @param inputIndex {number} - The input index to marshal to prep for hashing then signing
 * @returns {Buffer} - Get the marshalled data that needs to be hashed then signed
 */
function getMarshalDataSig(tx, inputIndex) {
    const index = Buffer.from(inputIndex.toString());
    const timestamp = Buffer.from(tx._timestamp.toString());
    const chainId = Buffer.from(tx._tokenChainId, 'hex');
    const content = Buffer.from(tx._content);
    return Buffer.concat([index,timestamp,chainId,content]);
}

module.exports = Transaction;
