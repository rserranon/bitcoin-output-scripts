# Bitcoin-output-Scripts

### Scripts to create transactions with different outputs types and spend them, leveraging the bitcoin core test_framework

The scripts in this repository are created to help people learning Bitcoin and developers starting in Bitcoin, to understand how transactions, with different types of outputs,  are constructed and broadcast to the Bitcoin network. 

The repository lives separately from the `bitcoin/bitcoin` core repository, however a couple of symlinks can  be created to be able to leverage the functional test_framework. If you already have a directory where you build Bitcoin core, the symlinks have to be adjusted to point to your Bitcoin core repository, in my case they are the following:
* in this project home directory: 
    * `ln -s ~/bitcoin-core/bitcoin/test/config.ini config.ini`
* in this project `functional` directory: 
    * `ln -s ~/bitcoin-core/bitcoin/test/functional/test_framework test_framework`

By doing this, the scripts in the functional folder use the first symlink to share the configuration created by `./configure` by bitcoin core. And they can look for the `test_framework` objects directly from your Bitcoin core directory, by using the second symlink.

Scripts in the funcional repository can be run directly typing the name of the script `./create_coinbase_script.py`. Note the file needs execution permissions `(chmod +x <file>)`.

The options provided by the test_framework can be used, for example `./create_P2PK.py --loglevel=DEBUG --tracerpc`. 

If you want to know the available options use `./create_P2PK.py -h`

---------------

### The valid standard types of transaction scripts in Tx Outputs are:


Standard transaction types accepted by the Bitcoin network and the miners.

| vout               	                | scriptPubKey                                                        	            | scriptSig                   	 | redeem<br>script 	| witness-stack                                	|
|--------------------	                |---------------------------------------------------------------------	            |-----------------------------	 |------------------	|----------------------------------------	    |
| [`P2PK`](functional/create_P2PK.py)   | `<pubKey>`<br>`OP_CHECKSIG`                                           	        | `<signature>`                  |                  	|                                        	    |
| [`P2PKH`](functional/create_P2PKH.py) | `OP_DUP`<br>`OP_HASH160`<br>`<pubKeyHash>`<br>`OP_EQUALVERIFY`<br>`OP_CHECKSIG` 	| `<signature>`<br>`<publicKey>` |                  	|                                        	    |
| [`P2SH`]()          	                | `OP_HASH160`<br>`scriptHash`<br>`OP_EQUAL`                                	    | `data_pushes`<br>`<redemScript>`| `arbitrary`        	|                                        	    |
| [Create P2WPKH](functional/create_P2WPKH.py)             	            | 0<br>`<pubKeyHash>`                                                             	|                             	 |                  	| `<signature>`<br>`<publicKey>`                |
| [`P2WSH`]()              	            | 0<br>`<witnessScriptHash>`                                                      	|                             	 |                  	| `<witnessScript>`                             |
| [`P2SH-P2WPKH`]()       	            | `OP_HASH160`<br>`<redemScriptHash>`<br>`OP_EQUAL`                                 | `<redemScript>`                | 0<br>`<pubKeyHash>`  | `<signature>`<br>`<publicKey>`                |
| [`P2SH-P2WSH`]()         	            | `OP_HASH160`<br>`<redemScriptHash>`                                              	| `<redemScript>`                | 0<br>`<scriptHash>` 	| `<witnessScript>`                             |
| [`P2TR (key path)`]()    	            | 1<br>`<publicKey>`                                                             	|                             	 |                  	| `<signature>`                              	|
| [`P2TR (script path`)]()              | 1<br>`<publicKey>`                                                             	|                             	 |                  	| `<script>`<br>`control_block`                 |

This table was produced by Gloria Zhao[^1] 

## List and links of implemented scripts:

* [Create P2PK](functional/create_P2PK.py)
* [Create P2PKH](functional/create_P2PKH.py)
* [Create MultiSig](functional/create_MultiSig.py), legacy Multisig
* [Create P2WPKH](functional/create_P2WPKH.py)


[^1]: [Bitcoin Core PR review club on July 7th 2021](https://bitcoincore.reviews/22363)
