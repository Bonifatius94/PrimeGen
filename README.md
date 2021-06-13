
# PrimeGen

## About
This project was created just for fun to try out some maths theory about
primality checks (Miller-Rabin) and the RSA algorithm.

## Disclaimer
Do not use this project for any critical RSA encryptions. This is just a 
straight-forward approach not dealing with common security risks, etc.

## Usage
If you haven't done already, install dotnet to your dev machine.
Following commands show how to install dotnet onto Ubuntu 20.04.

```sh
wget https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb

sudo apt-get update; \
  sudo apt-get install -y apt-transport-https && \
  sudo apt-get update && \
  sudo apt-get install -y dotnet-sdk-5.0

# official tutorial: https://docs.microsoft.com/de-de/dotnet/core/install/linux-ubuntu#2004-
```

Download the source code by cloning this git repository.

```sh
git clone https://github.com/Bonifatius94/PrimeGen
cd PrimeGen
```

Now you can run the project to create some primes that are used to
encrypt and decrypt a very simple message using the RSA algorithm.

```sh
# use a non-optimized binary, working on any system
dotnet run

# use an optimized binary (here: optimized for linux x64 systems)
 dotnet run --runtime linux-x64 --configuration Release
```

When running you may be prompted an output like the following example:

```text
Generating keys for RSA encryption (keylen=128 bits):
====================================================
p=22641425880588529119780961947471613697
q=64691136216422834958231258782814769181
N=1464699565775193873901347581743378875189028505571442438354476348766653072157
phi(N)=1464699565775193873901347581743378875101695943474431074276464128036366689280
e=84873714534479592302170843865699775323
d=716060456532699376833342290190195238176394542272471939021456502928274835667
====================================================
original message:  'Hello World, RSA encryption!'
encrypted message: ';/<C;0???!
                              ???? 0??;_??qr? ?'
decrypted message: 'Hello World, RSA encryption!'
```

## Licence
This software is available under the terms of the MIT licence.
