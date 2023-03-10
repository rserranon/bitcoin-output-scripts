#!/usr/bin/env python3
# Copyright (c) 2017-2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import hashlib
from io import BytesIO
from test_framework.address import program_to_witness
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.messages import (COutPoint,
                                     CTransaction,
                                     CTxIn,
                                     CTxOut,
                                     CTxInWitness,
                             )
from test_framework.script import (
                                   CScript,
                                   OP_1,
                                   SIGHASH_DEFAULT,
                                   TaprootSignatureHash,
                            )

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.key import ( ECKey, 
                               compute_xonly_pubkey, 
                               sign_schnorr,
                               verify_schnorr,
                               TaggedHash,
                               tweak_add_privkey,
                               tweak_add_pubkey
                        )



class P2TR_Key_Path(BitcoinTestFramework):

    def set_test_params(self):
        """This method has to be overwritten to specify test parameters"""
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[]]

    def skip_test_if_missing_module(self):
        """
           Note: this function, besides to skip the test if no wallet was compiled, creates 
           a default wallet.
           NOTE: if you remove it, you HAVE to create the wallet, otherwise RPCs calls will fail
        """
        self.skip_if_no_wallet()

    def run_test(self):
        """Main test logic"""

        self.log.info("Start test!")
        self.log.info("Generating some Blocks to create UTXOs")        
        self.generate(self.nodes[0], COINBASE_MATURITY + 1)
        
        # After generating 101 blocks there in a UTXO for 50BTC
        utxos = self.nodes[0].listunspent()
        assert len(utxos) == 1
        assert_equal(utxos[-1]["amount"], 50) 

        # Create input to spend from UTXO
        unspent_txid = self.nodes[0].listunspent()[-1]["txid"]
        input = [{"txid": unspent_txid, "vout": 0}]
        self.log.info("Selected UTXO as input: {}".format(input))        

        # Key pair generation
        privkey = ECKey()
        privkey.generate()
        # Compute x only pubKey, Bip340 32 bytes Public Key
        pubkey, negated= compute_xonly_pubkey(privkey.get_bytes())
        assert_equal(len(pubkey), 32)
        self.log.info("Pubkey is {}\n".format(pubkey.hex()))

        # Create witness program ([32B x-coordinate])
        program = pubkey
        self.log.info("Witness program is {}\n".format(program.hex()))

        # Create (regtest) bech32m address
        version = 0x01 # Segwit v1
        address = program_to_witness(version, program)
        self.log.info("bech32m address is {}".format(address))

        # Create and sign transaction
        tx1_amount = 1
        tx1_hex = self.nodes[0].createrawtransaction(inputs=input, outputs=[{address: tx1_amount}])
        res = self.nodes[0].signrawtransactionwithwallet(hexstring=tx1_hex)
        self.log.debug("Tx1 result: {}".format(res))

        tx1_hex = res["hex"]
        assert res["complete"]
        assert 'errors' not in res

        # Send the raw transaction. We haven't created a change output,
        # so maxfeerate must be set to 0 to allow any fee rate.
        tx1_id = self.nodes[0].sendrawtransaction(hexstring=tx1_hex, maxfeerate=0)
        decrawtx = self.nodes[0].decoderawtransaction(tx1_hex, True)
        self.log.debug("Tx1 decoded: {}".format(decrawtx))


        # Reconstruct transaction from hex 
        tx1 = CTransaction()
        tx1.deserialize(BytesIO(bytes.fromhex(tx1_hex)))
        tx1.rehash()

        # Assert the output we created is a P2WPKH
        assert_equal(decrawtx['vout'][0]['scriptPubKey']['type'], 'witness_v1_taproot')
        self.log.info("Transaction {}, output 0".format(tx1_id))       
        self.log.info("sent to {}".format(address))       
        self.log.info("Amount {}".format(decrawtx['vout'][0]['value']))       


        # Generate a P2TR scriptPubKey 01(segwit v1) 20(32 bytes in hex) <pubkey>
        script_pubkey = CScript([OP_1, pubkey])

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

        # Generate the taproot signature hash for signing
        # SIGHASH_ALL_TAPROOT is 0x00
        sighash = TaprootSignatureHash(  tx2, 
                                                [tx1.vout[0]], 
                                                SIGHASH_DEFAULT, 
                                                input_index= 0, 
                                                scriptpath= False
                                             )
         
        # All schnorr sighashes except SIGHASH_DEFAULT require
        # the hash_type appended to the end of signature
        signature = sign_schnorr(privkey.get_bytes(), sighash)

        # Add signature to witness stack
        tx2.wit.vtxinwit.append(CTxInWitness())
        tx2.wit.vtxinwit[0].scriptWitness.stack = [signature]
        tx2.rehash()

        tx2_hex = tx2.serialize().hex()
        decrawtx = self.nodes[0].decoderawtransaction(tx2_hex, True)
        descriptor = decrawtx['vout'][0]['scriptPubKey']['desc']
        assert self.nodes[0].testmempoolaccept(rawtxs=[tx2_hex], maxfeerate=0)[0]['allowed']
        tx2_id = self.nodes[0].sendrawtransaction(hexstring=tx2_hex)
        address = decrawtx['vout'][0]['scriptPubKey']['address']
        self.log.info("P2TR Key Path Transaction {}".format(tx2_id))       
        self.log.info("sent to {}".format(address))       

        # Save the descriptor to search it later in the UTXO set 
        self.log.debug("descriptor: {}".format(descriptor))
        self.log.debug("Hex     Tx: {}".format(tx2_hex))
        self.log.debug("Decoded Tx: {}".format(decrawtx))

        # Key pair generation
        privkey = ECKey()
        privkey.generate()
        # Compute x only pubKey, Bip340 32 bytes Public Key
        pubkey, negated = compute_xonly_pubkey(privkey.get_bytes())

        contract = "This is the contract/message commitment"
        tagged_hash = TaggedHash("TapTweak", pubkey + contract.encode('utf-8'))

        # Tweak key pair
        tweak_PrivKey = tweak_add_privkey(privkey.get_bytes(), tagged_hash)
        tweak_PubKey, negated  = tweak_add_pubkey(pubkey, tagged_hash)
        self.log.info("Negated: {}".format(negated))
        self.log.info("Tweaked Privkey is {}\n".format(tweak_PrivKey.hex()))
        self.log.info("Tweaked Pubkey  is {}\n".format(tweak_PubKey.hex()))


        # Sign message and verify a signature
        msg = hashlib.sha256(b'message').digest()
        signature = sign_schnorr(tweak_PrivKey, msg)
        verify_signature = verify_schnorr(tweak_PubKey, signature, msg)
        assert(verify_signature)

if __name__ == '__main__':
    P2TR_Key_Path().main()
