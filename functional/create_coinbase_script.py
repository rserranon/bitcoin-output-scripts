#!/usr/bin/env python3
# created a symlink to bitcoin-core test_framework
# ln -fs ~/bitcoin-core/bitcoin/test/functional/test_framework ./test_framework/
#
from test_framework.blocktools import (
    create_block,
)
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    SEQUENCE_FINAL,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.script import (
    CScript,
    OP_1)
from test_framework.util import (
    assert_equal,
)
class CoinbaseTest(BitcoinTestFramework):
    # Each functional test is a subclass of the BitcoinTestFramework class.

    def set_test_params(self):
        """Override test parameters for your individual test.
        This method must be overridden and num_nodes must be explicitly set."""
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[]]


    def run_test(self):
        """Main test logic"""
        self.log.info("Starting test!")

        coinbase = CTransaction()
        coinbase.nVersion = 1
        coinbase.vin = [CTxIn(COutPoint(0, 0xffffffff), CScript([OP_1, OP_1]), SEQUENCE_FINAL)]
        coinbase.vout = [CTxOut(5000000000, CScript([OP_1]))]
        coinbase.nLockTime = 0
        coinbase.rehash()
        self.log.info("Create Coinbase tx")
        assert coinbase.hash == "f60c73405d499a956d3162e3483c395526ef78286458a4cb17b125aa92e49b20"
        # Mine it
        block = create_block(hashprev=int(self.nodes[0].getbestblockhash(), 16), coinbase=coinbase)
        block.rehash()
        block.solve()
        self.nodes[0].submitblock(block.serialize().hex())
        self.log.info("Create Block")
        assert_equal(self.nodes[0].getblockcount(), 1)

if __name__ == '__main__':
    CoinbaseTest().main()
