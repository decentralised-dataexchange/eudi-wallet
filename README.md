<h1 align="center">
    EUDI Wallet OpenID for Verifiable Credentials SDK
</h1>

<p align="center">
    <a href="/../../commits/" title="Last Commit"><img src="https://img.shields.io/github/last-commit/decentralised-dataexchange/eudi-wallet?style=flat"></a>
    <a href="/../../issues" title="Open Issues"><img src="https://img.shields.io/github/issues/decentralised-dataexchange/eudi-wallet?style=flat"></a>
    <a href="./LICENSE" title="License"><img src="https://img.shields.io/badge/License-Apache%202.0-green.svg?style=flat"></a>
</p>


<p align="center">
  <a href="#about">About</a> •
  <a href="#release-status">Release Status</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#licensing">Licensing</a>
</p>

## About

This repository hosts the source code for the Python port for the EUDI wallet. This is aligned with implementing digital wallets across the EWC LSP consortium wallet providers as per the European Architecture and Reference Framework (ARF). This SDK ensures the provider entity can self-test and sign off against the EWC Interoperability Test Bed (ITB).

This implementation uses the ES256K (ECDSA) signing algorithm. 

## Release Status

Work in progress, and the codebase could be more stable.

## Installation

eudi-wallet can be installed (preferably in a `virtualenv`) using ``pip`` as follows:

```bash
   $ pip install eudi-wallet
```

## Contributing

Feel free to improve the plugin and send us a pull request. If you find any problems, please create an issue in this repo.

## References

1. EBSI Wallet Conformance Testing - https://ec.europa.eu/digital-building-blocks/wikis/display/EBSIDOC/EBSI+Wallet+Conformance+Testing

## Licensing
Copyright (c) 2022-25 LCubed AB (iGrant.io), Sweden

This file is licensed under the Apache License, Version 2.0 (the "License"); you may not use it except in compliance with the License.

You may obtain a copy of the License at https://www.apache.org/licenses/LICENSE-2.0.

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. Please see the LICENSE for the specific language governing permissions and limitations under the License.
