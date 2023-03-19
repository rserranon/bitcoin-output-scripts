#!/usr/bin/env python3
# Copyright (c) 2017-2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
from io import BytesIO
from test_framework.address import program_to_witness
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.messages import (
                                     CTransaction,
                                     COutPoint,
                                     CTxIn,
                                     CTxOut,
                                     CTxInWitness,
                                     ser_string
                             )
from test_framework.script import (
                                   CScript,
                                   SIGHASH_DEFAULT,
                                   TaprootSignatureHash,
                                   OP_CHECKSIG,
                                   OP_1
                            )

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.key import ( ECKey, 
                               compute_xonly_pubkey, 
                               sign_schnorr,
                               TaggedHash,
                               tweak_add_pubkey,
                               SECP256K1,
                               SECP256K1_ORDER
                        )
TAPSCRIPT_VERSION = bytes([0xc0])

def get_y(key):
    return SECP256K1.affine(key.p)[1]

def negate_privKey(key):
    """Negate a private key."""
    assert key.valid
    key.secret = SECP256K1_ORDER - key.secret

def negate_pubKey(key):
    """Negate a Public Key"""
    key.p = SECP256K1.affine(SECP256K1.negate(key.p))

def get_bytes(key):
    """Get bip340, 32 bytes of Public Key"""
    assert key.valid
    p = SECP256K1.affine(key.p)
    if p is None:
        return None
    return bytes(p[0].to_bytes(32, 'big'))

# Facilitate key pair generation
def generate_bip340_key_pair():
    """Key pair generation""" 
    privkey = ECKey()
    privkey.generate()
    pubkey = privkey.get_pubkey()
    if get_y(pubkey) % 2 != 0:
       negate_privKey(privkey) 
       negate_pubKey(pubkey)
    assert_equal(len(get_bytes(pubkey)), 32)

    return privkey.get_bytes(), get_bytes(pubkey)

def tapbranch_hash(left, right):
    """Create TapBranch sorting lexicographically"""
    return TaggedHash("TapBranch", b''.join(sorted([left, right])))

class P2TR_Script_Path(BitcoinTestFramework):

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

        # Generate key pairs
        internal_privkey, internal_pubkey = generate_bip340_key_pair()

        privkey_A, pubkey_A = generate_bip340_key_pair()
        privkey_B, pubkey_B = generate_bip340_key_pair()
        privkey_C, pubkey_C = generate_bip340_key_pair()

        # create PK scripts
        script_A = CScript([pubkey_A, OP_CHECKSIG])
        script_B = CScript([pubkey_B, OP_CHECKSIG])
        script_C = CScript([pubkey_C, OP_CHECKSIG])

        # Hash TapLeaves with version, length and script (ser_string() appends compact size length)
        hash_A = TAPSCRIPT_VERSION + ser_string(script_A)
        hash_B = TAPSCRIPT_VERSION + ser_string(script_B)
        hash_C = TAPSCRIPT_VERSION + ser_string(script_C)
        TH_Leaf_A = TaggedHash("TapLeaf", hash_A)
        TH_Leaf_B = TaggedHash("TapLeaf", hash_B)
        TH_Leaf_C = TaggedHash("TapLeaf", hash_C)

        # Compute branches
        branch_AB = tapbranch_hash(TH_Leaf_A, TH_Leaf_B)
        branch_ABC = tapbranch_hash(branch_AB, TH_Leaf_C)
        
        # Compute TapTweak
        tap_tweak = TaggedHash("TapTweak", internal_pubkey + branch_ABC)
        self.log.info("TapTweak: {}".format(tap_tweak.hex()))

        # Derive bech32m address
        # TODO tweak_add_pubkey() functon sometimes return negated True and the mempool accept fails
        # I will either find a way to negate it and see if that works, will be worth to understand why this
        # happens considering that all privkeys and pubkeys used have been negated if needed
        taproot_PK_bytes, negated = tweak_add_pubkey(internal_pubkey, tap_tweak)
        self.log.info("Negated: {}".format(negated))
        bech32m_address = program_to_witness(1, taproot_PK_bytes)
        self.log.info("Address (bech32m): {}".format(bech32m_address))

        # Create Tx1 using the tweaked public key
        tx1_amount = 1
        tx1_hex = self.nodes[0].createrawtransaction(inputs=input, outputs=[{bech32m_address: tx1_amount}])
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

        # Assert the output we created is a P2TR witness_v1_taproot
        assert_equal(decrawtx['vout'][0]['scriptPubKey']['type'], 'witness_v1_taproot')
        self.log.info("Transaction {}, output 0".format(tx1_id))       
        self.log.info("sent to {}".format(bech32m_address))       
        self.log.info("Amount {}".format(decrawtx['vout'][0]['value']))       


        # Generate a P2TR scriptPubKey 01(segwit v1) 20(32 bytes in hex) <pubkey>
        script_pubkey = CScript([OP_1, internal_pubkey])

        # Manually assemble the Tx2, using Tx1 P2TR output as input.
        tx2 = CTransaction()
        tx2.nVersion = 2
        tx2.nLockTime = 0
        outpoint = COutPoint(int(tx1_id,16), 0)
        # No scriptSig, the signature will be on the witness stack
        tx2.vin.append(CTxIn(outpoint, b""))
        # scriptPubKey is witness v1: [1 and 32 byte public key]
        dest_output = CTxOut(nValue=((tx1.vout[0].nValue)- 1000), scriptPubKey=script_pubkey)
        tx2.vout.append(dest_output)

        # Generate the taproot signature hash for signing
        # SIGHASH_ALL_TAPROOT is 0x00
        sighash = TaprootSignatureHash(  tx2, 
                                                [tx1.vout[0]], 
                                                SIGHASH_DEFAULT, 
                                                input_index = 0, 
                                                scriptpath = True,
                                                script = script_B 
                                             )
         
        # All schnorr sighashes except SIGHASH_DEFAULT require
        # the hash_type appended to the end of signature
        signature = sign_schnorr(privkey_B, sighash)

        control_block = b''.join([TAPSCRIPT_VERSION, internal_pubkey, TH_Leaf_A, TH_Leaf_C])
        witness_elements = [signature, script_B, control_block] 

        # Add witness elements, script and control block 
        tx2.wit.vtxinwit.append(CTxInWitness())
        tx2.wit.vtxinwit[0].scriptWitness.stack = witness_elements
        tx2.rehash()


        tx2_hex = tx2.serialize().hex()
        decrawtx = self.nodes[0].decoderawtransaction(tx2_hex, True)
        descriptor = decrawtx['vout'][0]['scriptPubKey']['desc']
        assert self.nodes[0].testmempoolaccept(rawtxs=[tx2_hex], maxfeerate=0)[0]['allowed']
        tx2_id = self.nodes[0].sendrawtransaction(hexstring=tx2_hex)
        address = decrawtx['vout'][0]['scriptPubKey']['address']
        self.log.info("P2TR Script Path Transaction {}".format(tx2_id))       
        self.log.info("sent to {}".format(address))       
        self.log.info("Descriptor {}".format(descriptor))       

if __name__ == '__main__':
    P2TR_Script_Path().main()
