# VT

Simple tool to check VirusTotal hashes.

## Setup

0. Create VirusTotal account and get API Key

1. Create a file named ~/.vt.conf

```
[config]
API_KEY=<Your API Key>
```


## Usage

`cat <list of hashes>.txt | python main.py`

Returns the list of malicious VirusTotal hashes
