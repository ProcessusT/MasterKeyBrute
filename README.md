# MasterKeyBrute
 Bruteforce DPAPI encrypted MasterKey File from Windows Credentials Manager

<div align="center">
  <br>
  <img src="https://img.shields.io/badge/Python-3.11-informational">
  <br>
  <a href="https://twitter.com/intent/follow?screen_name=ProcessusT" title="Follow"><img src="https://img.shields.io/twitter/follow/ProcessusT?label=ProcessusT&style=social"></a>
  <br><br>
</div>

<br>
<div align="center">
<img src="https://github.com/ProcessusT/MasterKeyBrute/raw/main/.assets/demo.gif" width="80%;">
</div>
<br>


## Usage
<br>
MasterKeyBrute uses Impacket syntax :
<br><br>

```bash
**************************************************
                 MASTERKEYBRUTE

                 @Processus
                    v1.0
**************************************************


usage: masterkeybrute.py [-h] -mkf MKF -sid SID -w W [--blob BLOB] [--show-prekeys SHOW_PREKEYS] [-debug]

Bruteforce DPAPI encrypted MasterKey File from Windows Credentials Manager

options:
  -h, --help            show this help message and exit
  -mkf MKF              Master Key File
  -sid SID              User SID to derivate key
  -w W                  Wordlist file

Optionnal:
  --blob BLOB           Blob file to decrypt with decrypted MasterKey
  --show-prekeys SHOW_PREKEYS
                        Show calculated prekeys

Verbosity:
  -debug                Turn DEBUG output ON
```

<br>
<br>

## Example

<br>

```bash
python3 masterkeybrute.py -mkf d5a8f4c9-a8ab-423a-a027-601472215dff -sid S-1-5-21-2097421949-534903256-19675394-500 -w /opt/rockyou.txt --blob 5AEA058AA7D881EBF78E4BE4515E5159 -debug
```

<br>
<br>
    