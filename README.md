# bitcoin-output-Scripts

### Scripts to create different types of outputs, leveraging the bitcoin core test_framework

This repository lives separatelly of the bitcoin-core/bitcoin repostory, however a couple of symlinks have been created to leverage the functional test_framework, the symlinks created are the following:
* in the home directory: 
`ln -s ~/bitcoin-core/bitcoin/test/config.ini config.ini`
* in functional directory: 
`ln -s ~/bitcoin-core/bitcoin/test/functional/test_framework test_framework`

Scripts in the funcional repository can be run direcly typing the name of the script. Note it has to have execution permisssions `./create_coinbase_script.py`, the options provided by the test_framework can be used, for example `./create_coinbase_script.py --loglevel=DEBUG --tracerpc`. 

If you want to know the available options use `./create_coinbase_script.py -h`

By doing this, the scripts in the functional folder share the same configuration created by `./configure` by bitcoin core in the `bitcoin-core/bitcoin` directory.
