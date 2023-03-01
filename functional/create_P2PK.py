#!/usr/bin/env python3
# Copyright (c) 2017-2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Create a transaction with P2PK output using the Bitcoin Functional test_framework
"""
from test_framework.descriptors import drop_origins
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.messages import CTransaction, CTxIn, CTxOut, COutPoint, COIN
from test_framework.script_util import key_to_p2pk_script

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.key import ECKey

class P2pkTest(BitcoinTestFramework):

    def set_test_params(self):
        """This method has to be overwritten to specify test parameters"""
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[]]

    def skip_test_if_missing_module(self):
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

        self.log.info("Select the UTXO we will be using")
        utxo = utxos[0]
        self.log.debug("Selected UTXOs : {}".format(utxo))


        # Create private key and generate public key 
        key = ECKey()
        key.generate()
        pubkey = key.get_pubkey()
       

        # Create script, it has to be  <pubKey> OP_CHECKSIG
        script_pubkey = key_to_p2pk_script(pubkey.get_bytes())
        self.log.debug("P2PK Script: {}".format(repr(script_pubkey)))

        self.log.info("Create Tx")
        self.relayfee = self.nodes[0].getnetworkinfo()["relayfee"]
        # COIN = 100,000,000 sats per BTC
        value = int((utxo["amount"] - self.relayfee) * COIN)
        # Create Tx, inputs and outputs using message.py classes 
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]))]
        tx.vout = [CTxOut(value, script_pubkey)]
        tx.rehash() # Hash Tx 
        self.log.debug("Transacción: {}".format(tx))

        self.log.info("Sign Tx")
        tx_hex = self.nodes[0].signrawtransactionwithwallet(tx.serialize().hex())["hex"]
        self.log.debug("Transacción HEX: {}".format(tx_hex))

        decrawtx = self.nodes[0].decoderawtransaction(tx_hex, True)
        descriptor = decrawtx['vout'][0]['scriptPubKey']['desc']
        # Save the descriptor to search it later in the UTXO set 
        self.log.debug("descriptor: {}".format(descriptor))
        self.log.debug("Decoded Tx: {}".format(decrawtx))

        # Broadcast Tx to be included in mempool 
        self.log.info("Broadcast Tx")
        txid = self.nodes[0].sendrawtransaction(tx_hex)
        self.log.debug("Tx id: {}".format(txid))
        
        mempool = self.nodes[0].getrawmempool()
        # Make sure our transaction is in the mempool 
        assert_equal(mempool[0], txid)

        self.log.info("Mine Tx")        
        blocks = self.generate(self.nodes[0], 1)
        
        # Make sure our Tx was mined 
        mempool = self.nodes[0].getrawmempool()
        assert len(mempool) == 0

        # TODO understand why our tx in not in this wallet UTXOs 
        utxos = self.nodes[0].listunspent(minconf=0)
        assert len(utxos) > 0
        self.log.debug("unspent UTXOs : {}".format(utxos))

        # However it is on the UTXO set
        expected_utxo = self.nodes[0].scantxoutset(action="start", scanobjects=[{'desc': descriptor}])
        descriptor_utxo = drop_origins(expected_utxo['unspents'][0]['desc'])
        assert_equal(descriptor_utxo, descriptor)
        self.log.info("Finish test!")

if __name__ == '__main__':
    P2pkTest().main()
