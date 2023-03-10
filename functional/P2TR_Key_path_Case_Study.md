
## P2TR_Key_Path Case Study

In this scenario we will do the following:


1. Generate a new Coinbase UTXO.
2. Create a tx1 with an P2TR output, using the selected UTXO as input.  On step 3 we will spend it.
3. Manually create tx2 that spends from the P2TR output from tx1 using the witness stack to provide the signature, and create a new P2TR Key Path output.
4. Explain the properties of schnorr signatures that allow for Tweaking the public key to commit a message using pay-to-contract commitment.

_Note: to maintain the scenario simple, we are not generating change outputs._

Figure 1
![Figure 1](P2TR-Key-Path.png)


1. Generate a new coinbase UTXO

Call generate on our node and generate 101 blocks (`COINBASE_MATURITY + 1`) to be able to have an spending UTXO. Select the last UTXO.

```python
blocks = self.generate(self.nodes[0], COINBASE_MATURITY + 1)
utxos = self.nodes[0].listunspent()
unspent_txid = self.nodes[0].listunspent()[-1]["txid"]
```

2. Create Tx1

Create the first transaction using the selected UTXO as input.

Create a Bip340 32 bytes public key and a bech32m address to generate a P2TR Key Path[^2], witness_v1_outout, in Tx2 we will create a P2TR Key Path output manually, and spend from this Tx1 output.

```python
# Key pair generation
privkey = ECKey()
privkey.generate()
# Compute x only pubKey, Bip340 32 bytes Public Key
pubkey_tuple = compute_xonly_pubkey(privkey.get_bytes())
pubkey = pubkey_tuple[0]

# Create witness program ([32B x-coordinate])
program = pubkey

# Create (regtest) bech32m address
version = 0x01 # Segwit v1
address = program_to_witness(version, program)

tx1_amount = 1
tx1_hex = self.nodes[0].createrawtransaction(inputs=input, outputs=[{address: tx1_amount}])
res = self.nodes[0].signrawtransactionwithwallet(hexstring=tx1_hex)
tx1_id = self.nodes[0].sendrawtransaction(hexstring=tx1_hex, maxfeerate=0)
```


3. Create Tx2

Create a P2TR Key Path scriptPubkey, 0 and the 32 byte of the Public Key, as per [Bip: 341, Witness program](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#script-validation-rules), SegWit v1.[^3]

```python
# Generate a P2TR scriptPubKey 01(segwit v1) 20(32 bytes in hex) <pubkey>
script_pubkey = CScript([OP_1, pubkey])
```

Then manually assemble the Tx2, using Tx1 P2TR output as input.

```python
# Manually assemble the Tx2, using Tx1 P2TR output as input.
tx2 = CTransaction()
tx2.nVersion = 1
tx2.nLockTime = 0
outpoint = COutPoint(int(tx1_id,16), 0)

# No scriptSig, the signature will be on the witness stack
tx2.vin.append(CTxIn(outpoint, b""))

# scriptPubKey is witness v1: 0 and 32 byte public key
dest_output = CTxOut(nValue=((tx1.vout[0].nValue)- 1000), scriptPubKey=script_pubkey)
tx2.vout.append(dest_output)
```

Generate the sighash.

As specified in [BIP: 341: Taproot: SegWit version 1 spending rulesi, Signature validation rules](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#signature-validation-rules),
we provide: the script `OP_DUP, OP_HASH160, hash, OP_EQUALVERIFY, OP_CHECKSIG` (`0x19 76 a9 14{20-byte-pubkey-hash}88 ac`) (see item5 detail for P2WPKH in [Bip: 143](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#specification)), this tx=Tx2, input index, hashtype, and the value of the output spent by this input (prev tx vout amount), to the sighash function for SegWit. In this case as in almost every standard tx, `hashtype` is `SIGHASH_ALL`.[^3]

```python
# Generate the taproot signature hash for signing
# SIGHASH_ALL_TAPROOT is 0x00
sighash = TaprootSignatureHash(  tx2, 
                                 [tx1.vout[0]], 
                                 SIGHASH_DEFAULT, 
                                 input_index= 0, 
                                 scriptpath= False
                              )
```

Sign the Tx with Schnorr, as is a SegWit v1.

```python
# All schnorr sighashes except SIGHASH_DEFAULT require
# the hash_type appended to the end of signature
signature = sign_schnorr(privkey.get_bytes(), sighash)
```

Add signature to the witness stack, this are the unlocking conditions to be able to spend from the P2TR output of Tx1.

```python
# All schnorr sighashes except SIGHASH_DEFAULT require
# the hash_type appended to the end of signature
signature = sign_schnorr(privkey.get_bytes(), sighash)
``` 

Check mempool acceptance of our transaction and send it to mempool.

```python
assert self.nodes[0].testmempoolaccept(rawtxs=[tx2_hex], maxfeerate=0)[0]['allowed']
tx2_id = self.nodes[0].sendrawtransaction(hexstring=tx2_hex)
```

4. Tweak public key using pay-to-contract

The linearity of Schnorr signatures allow for public and private key tweaking. Tweaking means encoding a commitment into a key pair. The secure way to tweak a key pair, to commit to a message, is using pay-to-contract: H(P | c), this means hasing the concatenation of the public key with the commitment.[^1] 

Figure 2
![Figure 2](P2TR-Key-Path-pay-to-contract.png)


First we generate a private key/public key pair.
```python
# Key pair generation
privkey = ECKey()
privkey.generate()

# Compute x only pubKey, Bip340 32 bytes Public Key
pubkey_tuple = compute_xonly_pubkey(privkey.get_bytes())
pubkey = pubkey_tuple[0]
```

Lets generate a commitment.
To be able to do the add tweak, we need to convert it to a pay-to-contract H(P | c) so we use the TaggedHash() function from the functional framework.

```python
contract = "This is the contract/message commitment"
tagged_hash = TaggedHash("TapTweak", pubkey.get_bytes() + contract.encode('utf-8'))
```

Now we can do the tweaking of the key pair.

```python
# Tweak key pair
tweak_PrivKey = tweak_add_privkey(privkey.get_bytes(), tagged_hash)
tweak_PubKey  = tweak_add_pubkey(pubkey, tagged_hash)
```

Now we can proceed to sign a message and verify the signature, this tweaked public key can be used as an P2TR Key Path output and the tweaked private key to sign the transaction.

```python
# Sign message and verify a signature
msg = hashlib.sha256(b'message').digest()
signature = sign_schnorr(tweak_PrivKey, msg)
verify_signature = verify_schnorr(tweak_PubKey[0], signature, msg)
self.log.info(verify_signature)
```


Full [Python script](create_P2TR_Key_Path.py)


[^1]: [Optech, Taproot-Workshop](https://github.com/bitcoinops/taproot-workshop)
[^2]: [BIPS 340, Taproot, Schnorr Signatures for secp256k1](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
[^3]: [BIPS 341, Taproot, SegWit version 1 spending rules](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
[^4]: [BIPS 342, Taproot, Validation of Taproot Scripts](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)
