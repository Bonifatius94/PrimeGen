
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

Now you can run the project creating some primes required to carry out
the RSA algorithm properly.

```sh
dotnet run
```

## Licence
This software is available under the terms of the MIT licence.
