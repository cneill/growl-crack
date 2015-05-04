# Growl Crack

By [@ccneill](https://twitter.com/ccneill)

## About

Growl sends the server password hash over an unencrypted socket that can be
obtained by performing a man-in-the-middle attack on either the client or the
server. The hash is salted with a timestamp from the client system.

By default, the bindings linked to from the 
[Growl website](http://growl.info/documentation/developer/bindings.php) all
use MD5 for hashing, which is the easiest of the supported algorithms to crack.

Growl Crack supports cracking the seed using brute force, and the password using
a wordlist.

## Usage

    Usage:
        ./growl_crack.py --seed_hash=SEED_HASH --secret_hash=SECRET_HASH
            [--algo=ALGO --max_time=MAX_TIME --wordlist=WORDLIST]
        ./growl_crack.py --raw_string=RAW_STRING
            [--max_time=MAX_TIME --wordlist=WORDLIST]
        ./growl_crack.py --help

    Options:
        --seed_hash=SEED_HASH      Seed hash (second part of raw string after ".")
        --secret_hash=SECRET_HASH  Secret hash (first part of raw string after ":")
        --algo=ALGO                Algorithm for hashing [default: MD5]
        --raw_string=RAW_STRING    Raw string, in format show above
        --max_time=MAX_TIME        Max time in seconds to go back for seed cracking
                                   [default: 10000]
        --wordlist=WORDLIST        Wordlist to use for cracking password
                                   [default: /usr/share/dict/words]
        --help                     Show help information

## Examples

Let's say you want to sniff your local Growl server for notifications. You can
do this with tcpdump like so:

```bash
sudo tcpdump -i l0 -vvv -A port 23053
```

When sniffing for Growl notifications, you will know you've found a registration
with the hashes for the server password when you see something like the
following:

    19:18:01.582676 IP (tos 0x0, ttl 64, id 5118, offset 0, flags [DF], proto TCP (6), length 13745, bad cksum 0 (->f346)!)
    localhost.60158 > localhost.23053: Flags [P.], cksum 0x33a6 (incorrect -> 0x06e1), seq 1:13694, ack 1, win 12759, options [nop,nop,TS val 265257192 ecr 265257192], length 13693
    .....p5a..1.3.........Z
    ........GNTP/1.0 REGISTER NONE MD5:56E954A58B5DB8523004D7C5BE0CA957.5DD209C7EFDA9D4DF4BC6331FD406A4C
    Application-Name: poke
    Application-Icon: x-growl-resource://...
    Origin-Platform-Version: ...
    Origin-Software-Version: ...
    Origin-Machine-Name: ...
    Origin-Software-Name: gntp.py
    ...

The juicy bit is this here:

    MD5:56E954A58B5DB8523004D7C5BE0CA957.5DD209C7EFDA9D4DF4BC6331FD406A4C

The format of this string is as follows:

    {ALGO}:{SECRET_HASH}.{SEED_HASH}
    
Here are 2 examples of cracking such a string:

```bash 
# Cracking the raw sniffed string
./growl_crack.py --raw_string="MD5:56E954A58B5DB8523004D7C5BE0CA957.5DD209C7EFDA9D4DF4BC6331FD406A4C"

# Entering the hashes manually
./growl_crack.py --seed_hash="5DD209C7EFDA9D4DF4BC6331FD406A4C" --secret_hash="56E954A58B5DB8523004D7C5BE0CA957"
```


[growl_bindings]: "http://growl.info/documentation/developer/bindings.php"
