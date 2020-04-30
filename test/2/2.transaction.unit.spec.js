const util = require('../../util');
const assert = require('chai').assert;
const fctAddrUtils = require('factom/src/addresses');
const fctUtil = require('factom/src/util');
const Entry = require('factom/src/entry').Entry;
const BigNumber = require('bignumber.js');
const fctIdentityCrypto = require('factom-identity-lib/src/crypto');
const nacl = require('tweetnacl/nacl-fast').sign;
const TransactionBuilder = require('../../2/TransactionBuilder');
const TransactionBatchBuilder = require('../../2/TransactionBatchBuilder');
//Peg Conversion 
//{"version":1,"transactions":[{"input":{"address":"FA2BRbu43H91VPYcGhEdjGXCbt6wGMojXSYDxEsa4GSNRC14Gaaz","amount":10000000000,"type":"pFCT"},"conversion":"PEG"}]}


//Peg Transfer
//{"version":1,"transactions":[{"input":{"address":"FA3hGHh2Jb1wtEd1jvwvaRM2LB6iB5ZNTVBXgEyhU8kaEeiDTES4","amount":200000000000,"type":"PEG"},"transfers":[{"address":"FA3L6Q8ufbnmbN9yBZPFCNi4eVVzMqRJiuD3siEN6JTrmbRrviJu","amount":200000000000}]}]}

//{"version":1,"transactions":[{"input":{"address":"FA2Qwmzp4xeXR4jWYrQnbPSXi5wLdVHy8p3ksAVSvyjLEX7jE3pN","amount":150,"type":"pFCT"},"transfers":[{"address":"FA3aECpw3gEZ7CMQvRNxEtKBGKAos3922oqYLcHQ9NqXHudC6YBM","amount":150}]}]}

        let tx = new TransactionBuilder()
            .input("pFCT", "Fs1PkAEbmo1XNangSnxmKqi1PN5sVDbQ6zsnXCsMUejT66WaDgkm", 150)
            .conversion("PEG")
            .build();

//            console.log(tx.getMarshalDataSig(0));
        assert.isTrue(tx.getConversion()!==undefined);

        assert.isDefined(tx.getInput());

        assert.isObject(tx.getInput());

        assert.isDefined(tx.getInput().address);

        assert.isDefined(tx.getInput().amount);

        assert.isDefined(tx.getInput().type);

        //assert.lengthOf(Object.keys(tx.getInput()), 1);
        assert.isTrue(fctAddrUtils.isValidPublicFctAddress(tx.getInput().address), "Not every FCT Address in inputs was a valid public Factoid address");
        assert.isTrue(!isNaN(tx.getInput().amount) &&
                      Number.isInteger(tx.getInput().amount.toNumber()) &&
                      tx.getInput().amount > 0, "Not every amount in inputs was a valid positive nonzero integer");

        assert.isDefined(tx.getConversion());

        let tb = new TransactionBatchBuilder()
                        .transaction(tx)
                        .build()

        //tb = new TransactionBatchBuilder(tb)
        //                .pkSignature(tx1, signature)
        //                .build()
       
        const meta = {type: 'fat-js test run', timestamp: new Date().getTime()};

        tx = new TransactionBuilder()
            .input("pFCT", "Fs1PkAEbmo1XNangSnxmKqi1PN5sVDbQ6zsnXCsMUejT66WaDgkm", 150)
            .transfer("FA3aECpw3gEZ7CMQvRNxEtKBGKAos3922oqYLcHQ9NqXHudC6YBM", 150)
            .metadata(meta)
            .build();

        tb = new TransactionBatchBuilder()
                .transaction(tx)
                .build()
        //console.log("=== Transaction Batch to Sign (hex) === " );
        //console.log(tb.getMarshalDataSig(0).toString('hex'));
        //console.log("========================= ");
        console.log("=== Transaction Batch to Sign (hex) === " );
        console.log(tb.getMarshalDataSig(0).toString('hex')); //<=== this is what gets signed...
        console.log("========================= ");
        console.log("=== Transaction Batch to Sign (string) === " );
        console.log(tb.getMarshalDataSig(0).toString());
        console.log("========================= ");
        //console.log("=== Transaction Content === " );
        //console.log(tb.get.toString());
        //console.log("========================= ");
        //console.log("=== Transaction Entry === " );
        //console.log(JSON.stringify(tb.getEntry()));
        //console.log("========================= ");

        
        let ledger = "FA22de5NSG2FA2HmMaD4h8qSAZAJyztmmnwgLPghCQKoSekwYYct"
        tx = new TransactionBuilder()
            .input("pFCT", "FA22de5NSG2FA2HmMaD4h8qSAZAJyztmmnwgLPghCQKoSekwYYct", 150)
            .transfer("FA3aECpw3gEZ7CMQvRNxEtKBGKAos3922oqYLcHQ9NqXHudC6YBM", 150)
            //.metadata("Ledger External Sign Test")
            .build();

        console.log("=== !!!!!!!!!!!!JSON Content!!!!!!!!!!!!! === ")
        console.log(JSON.stringify(tx.getContent()))
        console.log("====!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!==== ")
        
        tb = new TransactionBatchBuilder()
                .transaction(tx)
                .build()

        console.log("=== Transaction Batch to Sign (hex) === " );
        console.log(tb.getMarshalDataSig(0).toString('hex')); //<=== this is what gets signed...
        console.log("========================= ");

        assert.throws(() => tb.validateSignatures())
                
        ///test the builder.
        tx = new TransactionBuilder()
            .input("pFCT", "FA22de5NSG2FA2HmMaD4h8qSAZAJyztmmnwgLPghCQKoSekwYYct", 150)
            .conversion("PEG")
            .build();
            
        tb = new TransactionBatchBuilder()
                .transaction(tx)
                .build()

        console.log("=== !!!!!!!!!!!!Conversion JSON Content!!!!!!!!!!!!! === ")
        console.log(JSON.stringify(tx.getContent()))
        console.log("====!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!==== ")
        console.log("=== Conversion to Sign (hex) === " );
        console.log(tb.getMarshalDataSig(0).toString('hex')); //<=== this is what gets signed...
        console.log("========================= ");
        
        
            
describe('Transaction Unit', function () {


    it('Builder', function () {
        //test conversion of 150 pFCT to PEG
        let tx = new TransactionBuilder()
            .input("pFCT", "Fs1PkAEbmo1XNangSnxmKqi1PN5sVDbQ6zsnXCsMUejT66WaDgkm", 150)
            .conversion("PEG")
            .build();

        //inputs
        assert.isDefined(tx.getInput());
        assert.isObject(tx.getInput());
        assert.isDefined(tx.getInput().address);
        assert.isDefined(tx.getInput().amount);
        assert.isDefined(tx.getInput().type);
        //assert.lengthOf(Object.keys(tx.getInput()), 1);
        assert.isTrue(fctAddrUtils.isValidPublicFctAddress(tx.getInput().address), "Not every FCT Address in inputs was a valid public Factoid address");
        assert.isTrue(!isNaN(tx.getInput().amount) && 
                       Number.isInteger(tx.getInput().amount.toNumber()) && 
                       tx.getInput().amount > 0, "Not every amount in inputs was a valid positive nonzero integer");
        
        assert.isDefined(tx.getConversion());

	let meta = {type: 'fat-js test run', timestamp: new Date().getTime()};

        tx = new TransactionBuilder()
            .input("pFCT", "Fs1PkAEbmo1XNangSnxmKqi1PN5sVDbQ6zsnXCsMUejT66WaDgkm", 150)
            .transfer("FA3aECpw3gEZ7CMQvRNxEtKBGKAos3922oqYLcHQ9NqXHudC6YBM", 150)
            .metadata(meta)
            .build();

        assert.strictEqual(tx.getInput().amount.toString(), new BigNumber('150').toString());
        assert.isObject(tx.getMetadata());
        assert.strictEqual(JSON.stringify(tx.getMetadata()), JSON.stringify(meta));
        assert.isArray(tx.getTransfers());
/*
        //test signing with private key externally, this will simulate an external signature such as from the Ledger
        let sk = fctAddrUtils.addressToKey("Fs1PkAEbmo1XNangSnxmKqi1PN5sVDbQ6zsnXCsMUejT66WaDgkm");
        let key = nacl.keyPair.fromSeed(sk);

        let sk2 = fctAddrUtils.addressToKey("Fs2nnTh6MvL3NNRN9NtkLhN5tyb9mpEnqYKjhwrtHtgZ9Ramio61");
        let key2 = nacl.keyPair.fromSeed(sk2);

        let pubaddr = fctAddrUtils.keyToPublicFctAddress(key.publicKey);

        tx = new TransactionBuilder()
            .input("pFCT", pubaddr, 150)
            .transfer("FA3aECpw3gEZ7CMQvRNxEtKBGKAos3922oqYLcHQ9NqXHudC6YBM", 150)
            .build();

        let extsig = nacl.detached(fctUtil.sha512(tx.getMarshalDataSig(0)), key.secretKey);
        let extsig2 = nacl.detached(fctUtil.sha512(tx.getMarshalDataSig(0)), key2.secretKey);

        //gives error for bad input address, in this case providing a key instead of address
        assert.throws(() =>  new TransactionBuilder()
            .input("pFCT", key.publicKey, 150)
            .transfer("FA3aECpw3gEZ7CMQvRNxEtKBGKAos3922oqYLcHQ9NqXHudC6YBM", 150)
            .build());

        //this should throw error for adding input to transaction error, when expecting signatures only
        assert.throws(() => new TransactionBuilder(tx)
            .input("pFCT", pubaddr, 150)
            .pkSignature(key.publicKey, extsig)
            .build());

        //this should throw error for having a publicKey that doesn't match input
        assert.throws(() => new TransactionBuilder(tx)
            .pkSignature(key2.publicKey, extsig)
            .build());

	//this throws for passing in an invalid signature of incorrect length
        assert.throws(() => new TransactionBuilder(tx)
            .pkSignature(key.publicKey, "abcdef1234567890")
            .build());


        //passing in a bad signature
	let badtx = new TransactionBuilder(tx)
            .pkSignature(key.publicKey, extsig2)
            .build();

	assert.isFalse(badtx.validateSignature());

        //should throw for no external signatures provided
        assert.throws(() => new TransactionBuilder(tx)
            .build());

        //so now give it a good signature. this is a good transaction
        let txgood = new TransactionBuilder(tx)
            .pkSignature(key.publicKey, extsig)
            .build();

        //should have good signature
        assert.isTrue(txgood.validateSignature());
*/

        //test both transfer & conversion provided (transfer first) 
        assert.throws(() => new TransactionBuilder()
            .input("pUSD", "Fs1PkAEbmo1XNangSnxmKqi1PN5sVDbQ6zsnXCsMUejT66WaDgkm", 150)
            .transfer("FA3aECpw3gEZ7CMQvRNxEtKBGKAos3922oqYLcHQ9NqXHudC6YBM", 150)
            .conversion("PEG")
            .build());

        //test both transfer & conversion provided (conversion first)
        assert.throws(() => new TransactionBuilder()
            .input("pUSD", "Fs1PkAEbmo1XNangSnxmKqi1PN5sVDbQ6zsnXCsMUejT66WaDgkm", 150)
            .conversion("PEG")
            .transfer("FA3aECpw3gEZ7CMQvRNxEtKBGKAos3922oqYLcHQ9NqXHudC6YBM", 150)
            .build());



        //test equal input & transfer
        assert.throws(() => new TransactionBuilder()
            .input("pUSD", "Fs1PkAEbmo1XNangSnxmKqi1PN5sVDbQ6zsnXCsMUejT66WaDgkm", 150)
            .transfer("FA3aECpw3gEZ7CMQvRNxEtKBGKAos3922oqYLcHQ9NqXHudC6YBM", 151)
            .build());

        //test decimal amount
        assert.throws(() => new TransactionBuilder()
            .input("Fs1PkAEbmo1XNangSnxmKqi1PN5sVDbQ6zsnXCsMUejT66WaDgkm", 1.1)
            .transfer("FA3aECpw3gEZ7CMQvRNxEtKBGKAos3922oqYLcHQ9NqXHudC6YBM", 1.1)
            .build());

        //test invalid input address
        assert.throws(() => new TransactionBuilder()
            .input("PEG", "Fs1PkAEbmo1XNangSnxmKqi1PN5sVDbQ6zsnXCsMUejT66WaDgkM", 150)
            .transfer("FA3aECpw3gEZ7CMQvRNxEtKBGKAos3922oqYLcHQ9NqXHudC6YBM", 150)
            .build());

        //test invalid output address
        assert.throws(() => new TransactionBuilder()
            .input("PEG", "Fs1PkAEbmo1XNangSnxmKqi1PN5sVDbQ6zsnXCsMUejT66WaDgkm", 150)
            .transfer("FA3aECpw3gEZ7CMQvRNxEtKBGKAos3922oqYLcHQ9NqXHudC6YBA", 150)
            .build());


        //test same address in input and output
        assert.throws(() => new TransactionBuilder()
            .input("PEG", "Fs1q7FHcW4Ti9tngdGAbA3CxMjhyXtNyB1BSdc8uR46jVUVCWtbJ", 10)
            .transfer("FA3aECpw3gEZ7CMQvRNxEtKBGKAos3922oqYLcHQ9NqXHudC6YBM", 10)
            .build());

        //test same convert from / to
        assert.throws(() => new TransactionBuilder()
            .input("PEG","Fs1q7FHcW4Ti9tngdGAbA3CxMjhyXtNyB1BSdc8uR46jVUVCWtbJ", 10)
            .conversion("PEG")
            .build());


        //test no outputs
        assert.throws(() => new TransactionBuilder()
            .input("pUSD","Fs1PkAEbmo1XNangSnxmKqi1PN5sVDbQ6zsnXCsMUejT66WaDgkm", 150)
            .build());
        
        
        ///test the builder.
        tx = new TransactionBuilder()
            .input("pFCT", "Fs1PkAEbmo1XNangSnxmKqi1PN5sVDbQ6zsnXCsMUejT66WaDgkm", 150)
            .conversion("PEG")
            .build();
            
//            console.log(tx.getMarshalDataSig(0));
        assert.isTrue(tx.getConversion()!==undefined);
        
        assert.isDefined(tx.getInput());
        
        assert.isObject(tx.getInput());
        
        assert.isDefined(tx.getInput().address);
        
        assert.isDefined(tx.getInput().amount);
        
        assert.isDefined(tx.getInput().type);
        
        //assert.lengthOf(Object.keys(tx.getInput()), 1);
        assert.isTrue(fctAddrUtils.isValidPublicFctAddress(tx.getInput().address), "Not every FCT Address in inputs was a valid public Factoid address");
        assert.isTrue(!isNaN(tx.getInput().amount) &&
                      Number.isInteger(tx.getInput().amount.toNumber()) &&
                      tx.getInput().amount > 0, "Not every amount in inputs was a valid positive nonzero integer");

        assert.isDefined(tx.getConversion());

        let tb = new TransactionBatchBuilder()
                        .transaction(tx)
                        .build()

        //tb = new TransactionBatchBuilder(tb)
        //                .pkSignature(tx1, signature)
        //                .build()
       
        meta = {type: 'fat-js test run', timestamp: new Date().getTime()};

        tx = new TransactionBuilder()
            .input("pFCT", "Fs1PkAEbmo1XNangSnxmKqi1PN5sVDbQ6zsnXCsMUejT66WaDgkm", 150)
            .transfer("FA3aECpw3gEZ7CMQvRNxEtKBGKAos3922oqYLcHQ9NqXHudC6YBM", 150)
            .metadata(meta)
            .build();

        console.log("=== JSON Content === ")
        console.log(JSON.stringify(tx.getContent()))
        console.log("==================== ")
        tb = new TransactionBatchBuilder()
                .transaction(tx)
                .build()
        //console.log("=== Transaction Batch to Sign (hex) === " );
        //console.log(tb.getMarshalDataSig(0).toString('hex'));
        //console.log("========================= ");
        console.log("=== Transaction Batch to Sign (hex) === " );
        console.log(tb.getMarshalDataSig(0).toString('hex')); //<=== this is what gets signed...
        console.log("========================= ");
        console.log("=== Transaction Batch to Sign (string) === " );
        console.log(tb.getMarshalDataSig(0).toString());
        console.log("========================= ");
        //console.log("=== Transaction Content === " );
        //console.log(tb.get.toString());
        //console.log("========================= ");
        //console.log("=== Transaction Entry === " );
        //console.log(JSON.stringify(tb.getEntry()));
        //console.log("========================= ");

        
        let ledger = "FA22de5NSG2FA2HmMaD4h8qSAZAJyztmmnwgLPghCQKoSekwYYct"
        tx = new TransactionBuilder()
            .input("pFCT", "FA22de5NSG2FA2HmMaD4h8qSAZAJyztmmnwgLPghCQKoSekwYYct", 150)
            .transfer("FA3aECpw3gEZ7CMQvRNxEtKBGKAos3922oqYLcHQ9NqXHudC6YBM", 150)
            //.metadata("Ledger External Sign Test")
            .build();

        tb = new TransactionBatchBuilder()
                .transaction(tx)
                .build()
        assert.throws(() => tb.validateSignatures())

    });
});
