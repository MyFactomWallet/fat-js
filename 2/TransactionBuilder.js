const constant = require('../constant');
const nacl = require('tweetnacl/nacl-fast').sign;
const fctAddressUtil = require('factom/src/addresses');
const fctIdentityUtil = require('factom-identity-lib/src/validation');
const BigNumber = require('bignumber.js');
const util = require('../util');
/**
 * Build & Model A FAT-0 Transaction
 * @alias TransactionBuilder0
 * @public
 * @class
 *
 * @example
 * const TransactionBuilder = require('fat-js').FAT0.TransactionBuilder
 *
 * const tokenChainId = '013de826902b7d075f00101649ca4fa7b49b5157cba736b2ca90f67e2ad6e8ec';
 *
 * let tx = new TransactionBuilder(tokenChainId)
 * .input("Fs1q7FHcW4Ti9tngdGAbA3CxMjhyXtNyB1BSdc8uR46jVUVCWtbJ", 150)
 * .output("FA3aECpw3gEZ7CMQvRNxEtKBGKAos3922oqYLcHQ9NqXHudC6YBM", 150)
 * .build();
 *
 * //coinbase transaction
 * tx = new TransactionBuilder(tokenChainId)
 * .coinbaseInput(10)
 * .output("FA3aECpw3gEZ7CMQvRNxEtKBGKAos3922oqYLcHQ9NqXHudC6YBM", 10)
 * .sk1("sk13Rp3LVmVvWqo8mff82aDJN2yNCzjUs2Zuq3MNQSA5oC5ZwFAuu")
 * .build();
 *
 * //burn transaction
 * tx = new TransactionBuilder(tokenChainId)
 * .input("Fs1PkAEbmo1XNangSnxmKqi1PN5sVDbQ6zsnXCsMUejT66WaDgkm", 150)
 * .burnOutput(150)
 * .build();
 *
 * //transaction metadata
 * tx = new TransactionBuilder(tokenChainId)
 * .input("Fs1PkAEbmo1XNangSnxmKqi1PN5sVDbQ6zsnXCsMUejT66WaDgkm", 150)
 * .output("FA3aECpw3gEZ7CMQvRNxEtKBGKAos3922oqYLcHQ9NqXHudC6YBM", 150)
 * .metadata({type: 'fat-js test run', timestamp: new Date().getTime()})
 * .build();
 *
 * //You can also use external signatures (from hardware devices, etc):
 *
 * let keyPair = nacl.keyPair.fromSeed(fctAddrUtils.addressToKey("Fs1q7FHcW4Ti9tngdGAbA3CxMjhyXtNyB1BSdc8uR46jVUVCWtbJ"));
 * let pubaddr = fctAddrUtils.keyToPublicFctAddress(keyPair.publicKey);
 *
 * let unsignedTx = new TransactionBuilder(testTokenChainId)
 * .input(pubaddr, 150)
 * .output("FA3umTvVhkcysBewF1sGAMeAeKDdG7kTQBbtf5nwuFUGwrNa5kAr", 150)
 * .build();
 *
 * let extsig = nacl.detached(fctUtil.sha512(unsignedTx.getMarshalDataSig(0)), keyPair.secretKey);
 *
 * let signedTx = new TransactionBuilder(unsignedTx)
 * .pkSignature(keyPair.publicKey, extsig)
 * .build();
 *
 */
class TransactionBuilder {

    /**
     * @constructor
     * @param {Transaction|string} Transaction or tokenChainId - Unsigned transaction or 64 character Factom Chain ID of the token to build the transaction for
     */
    constructor(t) {
        
        this._tokenChainId = 'cffce0f409ebba4ed236d49d89c70e4bd1f1367d86402a3363366683265a242d'
        
        if ( t instanceof (require('./Transaction')) ) {
            //support for external signatures

            //check if a coinbase transaction
            this._key = t._key

            this._signature = t._signature;

            this._input = t._input;
            this._transfers = t._transfers

            if ( t._conversion !== undefined ) {
                this._conversion = t._conversion
            }
            
            this._timestamp = t._timestamp;

            if ( t._metadata !== undefined ) {
                this._metadata = t._metadata;
            }
        } else if ( t === undefined ) {

            this._key = {};
            this._input = {address:"", amount: new BigNumber(0), type: ""};
            this._transfers = [];
        } else {
            throw new Error('Constructor expects either a previously assembled unsigned Transaction or no prameter');
        }
    }

    /**
     * Set up a Factoid address input for the transaction
     * @method
     * @param {string} type_ - Pegged asset to convert or transfer from
     * @param {string} fs - The private Factoid address to use as the input of the transaction OR raw public key if supplying external signatures
     * @param {(number|string|BigNumber)} amount - The integer amount of token units to send. Native JS Numbers (e.x. 123), strings (e.x. "123"), and BigNumbers(e.x. new BigNumber("9999999999999999") are allowed as long as they represent integers
     * @returns {TransactionBuilder}
     */
    input(type_, fs, amount_) {
        if (this._input.length > 0) throw new Error('Input already specified');
       
        let amt = amount_
        if ( amt === undefined ) {
            amt = 0
        }
        
        
        if ( this._signature !== undefined ) {
            throw new Error("Attempting to add new input to a previously assembled transaction, expecting signatures only")
        }

        //if it isn't a private address and instead a public address then, the fs should be a public key      
        if (fctAddressUtil.isValidPrivateAddress(fs)) { //first check to see if valid private address

            amt = new BigNumber(amt);
            if (!amt.isInteger() || amt.isLessThan(0)) throw new Error("Input amount must be a positive nonzero integer");

            this._key = nacl.keyPair.fromSeed(fctAddressUtil.addressToKey(fs));
            this._input.address = fctAddressUtil.getPublicAddress(fs)
        } else {

            // at this point the fs is should be the fa if we get this far
            let fa = fs;
            if ( !fctAddressUtil.isValidPublicFctAddress(fa) ) { //check to see if user passed in a public fct address
                throw new Error("Input address must be either a valid private Factoid address or a Factoid public address");
            }

            amt = new BigNumber(amt);
            if (!amt.isInteger() || amt.isLessThan(0)) throw new Error("Input amount must be a positive nonzero integer");

            this._key = {pubaddr: fa, publicKey:undefined};
            this._input.address = fa
        }
        
        this._input.type = type_
        this._input.amount = amt
        
        return this;
    }

    /**
     * Set up a Factoid address output for the transaction
     * @method
     * @param {string} fa - The public Factoid address destination of the output
     * @param {(number|string|BigNumber)} amount - The integer amount of token units to receive at the destination address. Native JS Numbers (e.x. 123), strings (e.x. "123"), and BigNumbers(e.x. new BigNumber("9999999999999999") are allowed as long as they represent integers
     * @returns {TransactionBuilder}
     */
    transfer(fa, amount) {

        if (this._conversion !== undefined ) throw new Error('Conversion already specified');
        
        let amt = amount
        if ( amt === undefined ) {
            amt = 0
        }
        
        if ( this._signature !== undefined ) {
            throw new Error("Attempting to add new output to previously assembled transaction, expecting signature only")
        }

        if (!fctAddressUtil.isValidPublicFctAddress(fa)) throw new Error("Output address must be a valid public Factoid address");

        amt = new BigNumber(amt);
        if (!amt.isInteger() || amt.isLessThan(0)) throw new Error("Input amount must be a positive nonzero integer");

        this._transfers.push({"address": fa, "amount": amt})
        
        return this;
    }

    /**
     * Set up a Factoid address output for the transaction
     * @method
     * @param {string} fa - The public Factoid address destination of the output
     * @param {(number|string|BigNumber)} amount - The integer amount of token units to receive at the destination address. Native JS Numbers (e.x. 123), strings (e.x. "123"), and BigNumbers(e.x. new BigNumber("9999999999999999") are allowed as long as they represent integers
     * @returns {TransactionBuilder}
     */
    conversion(convert_to_type_) {

        if (this._transfers.length > 0 ) throw new Error('One or more transfer(s) already specified for this transaction');
        
        if ( this._signature !== undefined ) {
            throw new Error("Attempting to add new conversion to previously assembled transaction, expecting signature only")
        }

        this._conversion = convert_to_type_
        
        return this;
    }

    /**
     * Set arbitrary metadata for the transaction
     * @method
     * @param {*} metadata - The metadata. Must be JSON stringifyable
     * @returns {TransactionBuilder}
     */
    metadata(metadata) {
        if ( this._signature !== undefined ) {
            throw new Error("Attempting to add new metadata to previously assembled transaction, expecting signatures only")
        }
        try {
            JSON.stringify(metadata)
        } catch (e) {
            throw new Error("Transaction metadata bust be a valid JSON object or primitive");
        }
        this._metadata = metadata;
        return this;
    }

    /**
     * Add a public key and signature to the transaction. This is used only in the case of externally signed transactions (useful for hardware wallets).
     * Public Key's /signatures need to be added in the same order as their corresponding inputs.
     * @param {string|Array|Buffer} publicKey - FCT public key as hex string, uint8array, or buffer
     * @param {Buffer} signature - Signature 
     * @returns {TransactionBuilder} - TransactionBuilder instance.
     */
    pkSignature(publicKey, signature) {
        let pk = Buffer.from(publicKey, 'hex');

        let fa = fctAddressUtil.keyToPublicFctAddress(pk);

        if ( signature.length !== 64 ) {
            throw new Error("Invalid Signature Length." )
	}
        if ( this._input.address === fa ) {
            this._key.publicKey = pk;
            this._signature = [signature]
        } else {
            throw new Error("Public Key (" + pk.toString('hex') + ") for provided signature does not match input adderess." )
        }
        return this;
    }

    /**
     * Build the transaction
     * @method
     * @returns {Transaction}
     */
    build() {
        if (this._input.address === undefined || this._input.amount === undefined || this._input.type === undefined ) throw new Error("Input must have an address, type, and amount specified");
        
        if (!this._input.amount.isInteger() || this._input.amount.isLessThan(0)) throw new Error("Input amount must be a positive nonzero integer");
        
        if ( this._conversion === undefined   && this._transfers.length === 0 ) throw new Error("Either a conversion or transfer must be specified");
        
        if (this._conversion !== undefined ) {
           if (this._conversion === this._input.type ) {
               throw new Error("Conversion asset cannot be the same as the input asset.");
	   }
           if (this._conversion.length === "" ) {
               throw new Error("Conversion string must be specified with input");
           }
        }

        if (this._transfers.length > 0 ) {
	    let i = 0;
	    let sum = new BigNumber(0);
            for ( i = 0; i < this._transfers.length; ++i ) {
                if ( this._transfers[i] === undefined )  throw new Error("Malformed transfer entry");
		    
                if (this._transfers[i].address === undefined ) {
                    throw new Error("transfer address must be of type string");
                }
                
                if (this._transfers[i].amount === undefined ) {
                    throw new Error("transfer amount must be specified");
		}

                if (!this._transfers[i].amount.isInteger() || this._transfers[i].amount.isLessThan(0)) {
                    throw new Error("transfer amount must be a positive nonzero integer");
                }

                if ( this._input.address === this._transfers[i].address ) {
                    throw new Error("input cannot be the same as the transfer address");
		}
		sum = sum.plus(this._transfers[i].amount);
            }

	    if ( !this._input.amount.isEqualTo(sum) ) {
                throw new Error("transfer amount must equal input amount");
	    }
        }
        if ( this._timestamp !== undefined ) {
            if ( this._signature === undefined ) {
                throw new Error('Missing signature: Inputs must have an associated signature')
	    }
	}
        
        if ( this._signature !== undefined ) {
            if ( this._signature[0] === undefined ) {
                throw new Error('Missing signature: Inputs must have an associated signature')
            }
        }

        return new (require('./Transaction'))(this);
    }
}


module.exports = TransactionBuilder;
