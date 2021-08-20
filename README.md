# Cryptnox Python Communication Library

## CryptnoxPy 

**Warning: This is a beta release of the software. 
It is released for development purposes. 
Use at your own risk.**

A Python3 library to use the [Cryptnox smartcard applet](https://www.cryptnox.com/). 
It provides high level functions to send instructions with the Cryptnox and to manage its lifecycle. 
The core module is *CryptnoxPy* which provides a *Connection* class to 
establish a channel of communication that can be used to initialize a card instance through the 
factory method.

To buy NFC enabled cards that are supported by this library go to: 
[https://www.cryptnox.com/](https://www.cryptnox.com/)

## License

The library is available under dual licensing. You can use the library under the 
conditions of [GNU LESSER GENERAL PUBLIC LICENSE 3.0+](https://www.gnu.org/licenses/lgpl-3.0.en.html) 
or [contact us](info@cryptnox.ch) to ask about commercial licensing. 

## Documentation

API documentation can be found in HTML format in the [docs folder](docs/html/index.html) 
It is generated using Sphynx from the code and can be generated in other formats too.

## Installation and requirements

Requires :

* Python 3.6-3.9
* PCSCd on Linux

Ubuntu / Debian  
`(sudo) apt-get install python3-pip python3-setuptools pcscd`

Fedora / CentOS / RHEL  
`yum install python3-pip python3-setuptools pcsc-lite-ccid`

On some Linux, starts PCSCd service
```
(sudo) systemctl start pcscd
(sudo) systemctl enable pcscd
```

### Installation of this library

Make sure that you installed the required packages for your system. 
See the "Requires" section above.

Install with pip:  
`pip install cryptnoxpy`

Install from source:

Download and run in its directory :  
`pip install .`  
or  
`pip install git+ssh://git@github.com/Cryptnox-Software/cryptnoxpy.git`

This might require *sudo* on some systems.

Remove :  
`pip uninstall cryptnoxpy`

### Installation issues

If the **Linux system doesn\'t have Python 3.6, 3.7, 3.8 nor 3.9**, install 
Python 3.7 with the following recipe (Debian like):
```
sudo apt-get install -y make build-essential libssl-dev zlib1g-dev swig libpcsclite-dev
sudo apt-get install -y libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm git
sudo apt-get install -y libncurses5-dev libncursesw5-dev xz-utils tk-dev pcscd opensc
wget https://www.python.org/ftp/python/3.7.8/Python-3.7.8.tgz
tar xf Python-3.7.8.tgz
cd Python-3.7.8
./configure --enable-optimizations
make -j8 build_all
sudo make -j8 altinstall

sudo pip3.7 install git+ssh://git@gitlab.com/cryptnox-phase2/cryptnoxpy.git

# or (if issue about agent forwarding with sudo) :

cd ~
git clone git@gitlab.com:cryptnox-phase2/cryptnoxpy.git
cd cryptnoxpy
sudo pip3.7 install .
```

In case of **pyscard can\'t be installed** automatically with pip :  
1) Try to pip3 install with sudo or root :  
`sudo pip install .`  
2) If still a failure, install the following packages :  
Needed if pyscard can\'t be installed from package manager
`sudo apt install python3-dev swig libpcsclite-dev`  
then retry `sudo pip install .`.

If you use **contactless readers** on Linux, the RFID modules need to be disabled :
```
sudo rmmod pn533_usb
sudo rmmod pn533
sudo rm -r /lib/modules/*/kernel/drivers/nfc/pn533
```

### Update issues

In case you just want to update the package, with old pip version on some Linux, 
it is better to remove and reinstall the package :  
`sudo pip uninstall cryptnoxpy`  
`sudo pip install .`

## Lifecycle Management and library use

### import the library

```import cryptnoxpy```

### Get card object

To get the card a connection has to be established with the reader's index. The connection can 
then be passed to the factory that will initialize an object for the card in the reader from the 
correct class for the card type and version.

```
import cryptnoxpy

try:
    connection = cryptnoxpy.Connection(0)
except cryptnoxpy.ReaderException:
    print("Reader not found on index")
else:
    try:
        card = cryptnoxpy.factory.get_card(connection)
    except cryptnoxpy.CryptnoxException as error:
        # There is an issue with loading the card
        # CryptnoxException is the base exception class for module
        print(error)
    else:
        # Card is loaded and can be used
        print(f"Card serial number: {card.serial_number}")
```  

The factory will:
- connect to the card
- select the applet
- read the applet parameters
- select class to handle the card

The card contains basic information:
- card.serial_number : Integer : Card/applet instance Unique ID
- card.applet_version : 3 integers list : Applet version (ex. 1.2.2)

### Initialization and pairing

Right after the installation, the applet is not initialized, and the user needs 
to send some parameters to use the card. The initialization can be executed once. 
common secret is done during the init phase.

The init parameters required are :
* Name  (up to 20 chars string)
* Email (up to 60 chars string)
* PIN (9 digits string)
* PUK (15 digits string)
* optional : the first Paring Secret (32 bytes bytearray)

```pairing_key = card.init(name, email, pin, puk, pairing_secret)```

The returned data is the first PairingKey (32 bytes byte-array) and its index (0) :
`0x00 + ParingKeySlot0`

During the initialization phase, until the user public key for authentication 
registration is allowed, the set_pairing_key command is also allowed. 
layer with the card using standards APDU messages. Many applet commands require 
a secure channel.

### PIN

The PIN chosen during the initialization needs to be provided after each card 
reset, and a secure channel is opened.

To test a PIN string, simply use :  
```card.verify_pin(pin)```

### Seed administration

The applet manages a 256 bits master secret called the "seed". This is the BIP32 
Master Seed, and can be externally computed from a mnemonic to a binary seed 
using BIP39. The key pairs used for ECDSA are then computationally derived from 
this seed using BIP32 derivation scheme.

#### Seed generation

The seed can be generated in the card using the random number generator in the 
java chip system (AIS 20 class DRG.3). Doing this way, the seed secret never 
escapes the card protection.

The method to generate a new seed key is :  
```card.generate_seed(pin)```

The card can also randomly generate BIP39 mnemonics words list. But in this 
case, the query answer is only output and not used internally by the card. 
We don't recommend doing so, this is very insecure, as the seed is exposed in 
clear and full in the user's system.

#### Recovery

The Cryptnox applet can load binary seed.

The seed is loaded in the card using this method :  
```card.load_seed(seed, pin)```  
Seed is 32 bytes.

Once this seed is loaded in the card using the load_seed method, this card now 

For more details about the recovery, see load_seed operation in the API documentation.

### Derivation and keys system

The card applet is fully compliant with 
[BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki), 
except the maximum depth of derivation from the master key is 8 levels. 
It can be turned on for the card to return extended public keys for use in applications 
requiring it.

See derive and sign methods in the API documentation.

### EC Signature

The derivation of the key pair node can be also possible using the signature 
command (relative or absolute). 
a hash provided by the user. Note that this hash needs to be confirmed by the 
users beforehand, when they provide their EC384 signature of this hash.

The code to sign with the EC current key node is :  
```signature = card.sign(data_hash, cryptnoxpy.Derivation.CURRENT_KEY)```  
data_hash is a byte-array containing the EC hash to sign using ECDSA ecp256k1  
The signature a byte array, encoded as an ASN1 DER sequence of two INTEGER values, r and s.

See the sign method in the API documentation for more information.
