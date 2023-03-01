#!/usr/bin/env python3
# Copyright (c) 2017-2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
from test_framework.script_util import keyhash_to_p2pkh_script
from test_framework.address import hash160, program_to_witness
from test_framework.script import CScript
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.messages import (COutPoint,
                                     CTransaction,
                                     CTxIn,
                                     CTxOut,
                                     CTxInWitness,
                                     COIN
                             )
from test_framework.script import (SegwitV0SignatureHash, 
                                   SIGHASH_ALL
                            )
from test_framework.script_util import keyhash_to_p2pkh_script 
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.key import ECKey

class P2wpkh(BitcoinTestFramework):

    def set_test_params(self):
        """This method has to be overwritten to specify test parameters"""
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[]]

    def skip_test_if_missing_module(self):
        """
           Note: this function besides to skip the test if no wallet was compiled, creates 
           a default wallet.
           NOTE: if you remove it, you HAVE to create the wallet, otherwise RPCs calls will fail
        """
        self.skip_if_no_wallet()

    def run_test(self):
        """Main test logic"""

        self.log.info("Start test!")
        self.log.info("Generating some Blocks to create UTXOs")        
        blocks = self.generate(self.nodes[0], COINBASE_MATURITY + 1)
        
        # After generating 101 blocks there in a UTXO for 50BTC
        utxos = self.nodes[0].listunspent()
        assert len(utxos) == 1
        assert_equal(utxos[0]["amount"], 50) 


        self.log.info("Generate Key pair")
        key = ECKey()
        key.generate(True)
        pubkey = key.get_pubkey().get_bytes()
        assert_equal(len(pubkey), 33)  # This should be a compressed pubkey
        pubkey_hash = hash160(pubkey) 
        assert_equal(len(pubkey_hash), 20) # 20 byte hash for SegWit v0

        unspent_txid = self.nodes[0].listunspent()[-1]["txid"]
        input = [{"txid": unspent_txid, "vout": 0}]
        self.log.info("Selected UTXO: {}".format(input))        

        # Create (regtest) bech32 address and UTXO
        version = 0x00
        address = program_to_witness(version, pubkey_hash )
        self.log.debug("bech32 address: {}".format(address))
        tx1_amount = 1
        tx1_hex = self.nodes[0].createrawtransaction(inputs=input, outputs=[{address: tx1_amount}])
        res = self.nodes[0].signrawtransactionwithwallet(hexstring=tx1_hex)

        tx1_hex = res["hex"]
        assert res["complete"]
        assert 'errors' not in res

        # Send the raw transaction. We haven't created a change output,
        # so maxfeerate must be set to 0 to allow any fee rate.
        tx1_id = self.nodes[0].sendrawtransaction(hexstring=tx1_hex, maxfeerate=0)
        decrawtx = self.nodes[0].decoderawtransaction(tx1_hex, True)
        # Assert the output we created is a P2WPKH
        assert_equal(decrawtx['vout'][0]['scriptPubKey']['type'], 'witness_v0_keyhash')
        self.log.info("Transaction {}, output 0".format(tx1_id))       
        self.log.info("sent to {}".format(address))       


        # Create a P2WPKH output that uses a compressed pubkey

        # SegWit v0 scriptPubKey
        script_pubkey = CScript([0, pubkey_hash]) 

        self.log.info("Create P2WPKH transaction")
        tx2 = CTransaction()
        tx2.nVersion = 1
        tx2.nLockTime = 0
        outpoint = COutPoint(int(tx1_id,16), 0)
        # No scriptSig, the signature and pubKey will be on the witness stack
        tx2.vin.append(CTxIn(outpoint, b""))
        # scriptPubKey is witness v0: 0 and 20 byte hash of the public key
        dest_output = CTxOut(nValue=((tx1_amount * COIN)- 1000), scriptPubKey=script_pubkey)
        tx2.vout.append(dest_output)


        # Generate the segwit v0 signature hash for signing
        self.log.info("Signing transaction")
        # Script: OP_DUP, OP_HASH160, hash, OP_EQUALVERIFY, OP_CHECKSIG
        script = keyhash_to_p2pkh_script(pubkey_hash)
        sig_hash = SegwitV0SignatureHash(script=script,
                                                 txTo=tx2, 
                                                 inIdx=0, 
                                                 hashtype=SIGHASH_ALL, 
                                                 amount=tx1_amount * COIN)
        # Sign using ECDSA appending SIGHASH_ALL
        signature = key.sign_ecdsa(sig_hash) + chr(SIGHASH_ALL).encode('latin-1')  
        self.log.info("Add witness")
        # Add a witness to the transaction. For a P2WPKH, the witness field is the signature and pubkey
        tx2.wit.vtxinwit.append(CTxInWitness())
        tx2.wit.vtxinwit[0].scriptWitness.stack = [signature, pubkey]
        tx2.rehash()

        tx2_hex = tx2.serialize().hex()
        decrawtx = self.nodes[0].decoderawtransaction(tx2_hex, True)
        descriptor = decrawtx['vout'][0]['scriptPubKey']['desc']
        assert self.nodes[0].testmempoolaccept(rawtxs=[tx2_hex], maxfeerate=0)[0]['allowed']
        tx2_id = self.nodes[0].sendrawtransaction(hexstring=tx2_hex)
        address = decrawtx['vout'][0]['scriptPubKey']['address']
        self.log.info("P2WPKH Transaction {}".format(tx2_id))       
        self.log.info("sent to {}".format(address))       

        # Save the descriptor to search it later in the UTXO set 
        self.log.debug("descriptor: {}".format(descriptor))
        self.log.debug("Hex     Tx: {}".format(tx2_hex))
        self.log.debug("Decoded Tx: {}".format(decrawtx))

if __name__ == '__main__':
    P2wpkh().main()
