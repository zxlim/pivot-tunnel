# L2pivot
This is a proof of concept to showcase layer 2 [pivoting](https://en.wikipedia.org/wiki/Exploit_(computer_security)#Pivoting). The scripts involved are written in Python.


# Setup
Install the required pip packages. Using a virtual environment is highy recommended.
```
$ virtualenv venv
$ source venv/bin/activate
```

### Callback Server
```
$ pip install -r server/requirements.txt
```

### Callback Client
```
$ pip install -r client/requirements.txt
```

Windows users may need to manually compile Pcapy. See [here](https://github.com/CoreSecurity/pcapy/wiki/Compiling-Pcapy-on-Windows-Guide) for more information.


# Usage Example
### Callback Server
Running the Callback Server with default configuration:
```
$ sudo python server.py
```
This will run the server on port 443 with TLS Encryption enabled. The certificate and key used for encryption is automatically generated to "/tmp/L2pivot" and removed upon termination.

Root privileges are required as the Callback Server will be creating TAP interfaces and require read/write access to it.

For more information on the Callback Server:
```
$ python server.py -h
```

### Callback Client
Running the Callback Client with default configuration:
```
$ python client.py [PIVOT ADDRESS] [CALLBACK ADDRESS]
```
This will run the callback client, pivoting on the interface that has the IP address [PIVOT ADDRESS], and connect back to the Callback Server on [CALLBACK ADDRESS] on port 443 with TLS Encryption enabled.

Root privileges may be required on Linux systems for packet sniffing.

For more information on the Callback Client:
```
$ python client.py -h
```

The Callback Client has been tested on Windows (Windows 7 x64, Windows 10 x64) and Linux platforms.


# Important
The Callback Server is only tested to run on GNU/Linux systems with dhclient present.

To run the Client Callback on Windows systems, WinPCAP/ Npcap must be installed.


# License
This project is licensed under the [Apache License 2.0](LICENSE).