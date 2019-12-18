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
    constructor() {
            this._tokenChainId = 'cffce0f409ebba4ed236d49d89c70e4bd1f1367d86402a3363366683265a242d'
            this._transactions = [];
    }

    /**
     * Set up a Factoid address input for the transaction
     * @method
     * @param {string} type_ - Pegged asset to convert or transfer from
     * @param {string} fs - The private Factoid address to use as the input of the transaction OR raw public key if supplying external signatures
     * @param {(number|string|BigNumber)} amount - The integer amount of token units to send. Native JS Numbers (e.x. 123), strings (e.x. "123"), and BigNumbers(e.x. new BigNumber("9999999999999999") are allowed as long as they represent integers
     * @returns {TransactionBuilder}
     */
    transaction(txn) {
	    //need to verify signature
        if ( !txn.isSignatureValid() ) throw new Error('Transaction is not signed or signature invalid');
       
        this._transactions.push(txn); 
        
        return this;
    }

    /**
     * Build the transaction
     * @method
     * @returns {Transaction}
     */
    build() {
        return new (require('./TransactionEntry'))(this);
    }
}


module.exports = TransactionBuilder;
