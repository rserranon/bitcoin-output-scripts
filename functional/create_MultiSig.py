#!/usr/bin/env python3
# Copyright (c) 2017-2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""
Create a MultiSig transaction using the Bitcoin Functional test_framework
"""
from test_framework.blocktools import COINBASE_MATURITY

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

class MultiSigTest(BitcoinTestFramework):

    def set_test_params(self):
        """This method has to be overwritten to specify test parameters"""
        # We are going to use 3 nodes to get different public keys 
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [[],[],[]]

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

        node0, node1, node2 = self.nodes
        publicK0 = node0.getaddressinfo(node0.getnewaddress())['pubkey']
        publicK1 = node1.getaddressinfo(node1.getnewaddress())['pubkey']
        publicK2 = node2.getaddressinfo(node2.getnewaddress())['pubkey']
        keys=[publicK0, publicK1, publicK2]
        # Create the MultiSig transacion to work with 2 of the 3 signatures
        self.log.info("Create transaction")
        multi_sig = node0.createmultisig(2, keys, 'legacy')
        # Get destination address
        destination_addr = multi_sig['address']

        # Save the descriptor to search it later in the UTXO set 
        descriptor = multi_sig['descriptor']
        target_address = self.nodes[0].deriveaddresses(descriptor)
        assert_equal(target_address[0], destination_addr)
        self.log.debug("Destination Address: {}".format(destination_addr))

        txid = node0.sendtoaddress(destination_addr, 40)
        tx = node0.getrawtransaction(txid, True)
        self.log.debug("Decoded Tx: {}".format(tx))
        
        # Search for destination_addr on the vouts of the tx
        vout = [v["n"] for v in tx["vout"] if destination_addr == v["scriptPubKey"]["address"]]
        assert len(vout) == 1
        vout = vout[0]
        tx_address = tx["vout"][vout]["scriptPubKey"]["address"]
        assert_equal(tx_address,destination_addr)

        mempool = self.nodes[0].getrawmempool()
        # Make sure our transaction is in the mempool 
        assert_equal(mempool[0], txid)

        self.log.info("Mine Tx")        
        self.generate(node0, 1)
        
        # Make sure our Tx was mined 
        mempool = self.nodes[0].getrawmempool()
        assert len(mempool) == 0

        
        # TODO understand why our tx in not in this wallet UTXOs 
        utxos = self.nodes[0].listunspent(minconf=0)
        assert len(utxos) > 0
        self.log.debug("UTXOs disponibles: {}".format(utxos))

        # However it is on the UTXO set
        utxo_esperado = self.nodes[0].scantxoutset(action="start", scanobjects=[{'desc': descriptor}])
        utxo_address = self.nodes[0].deriveaddresses(utxo_esperado['unspents'][0]['desc'])
        assert_equal(utxo_address[0], destination_addr)
        self.log.debug("UTXO esperado: {}".format(utxo_esperado['unspents'][0]['desc']))

if __name__ == '__main__':
    MultiSigTest().main()
