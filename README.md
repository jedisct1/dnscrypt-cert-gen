dnscrypt-cert-gen
=================

Sample code to create dnscrypt certificates.

WARNING:
This code is deprecated.

Please use [dnscrypt-wrapper](https://github.com/Cofyc/dnscrypt-wrapper),
for generating certificates.

    $ git clone --recursive https://github.com/Cofyc/dnscrypt-wrapper.git
    $ cd dnscrypt-wrapper
    $ make install
    $ rehash

First, on a dedicated, trusted, offline host with encrypted partitions
and swap, generate a provider keypair:

    $ dnscrypt-wrapper --gen-provider-keypair

In addition to generating `public.key` and `secret.key` files, this
command prints the provider key required for `dnscrypt-proxy`'s
`--provider-key=` switch.

Then, issue the following command to generate a new dnscrypt key pair:

    $ dnscrypt-wrapper --gen-crypt-keypair

Finally, generate pre-signed certificates:

    $ dnscrypt-wrapper --crypt-secretkey-file=crypt_secret.key \
                       --crypt-publickey-file=crypt_public.key \
                       --provider-publickey-file=public.key \
                       --provider-secretkey-file=secret.key \
                       --gen-cert-file

This will print the DNS records needed for serving the certificates
using an authoritative name server, and generate the `dnscrypt.cert`
file for `dnscrypt-wrapper` to serve these directly.
