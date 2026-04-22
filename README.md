# smart-access

⚠️ PoC. It does work nicely on my machine, even with network changes and reconnects, but I'm only ~50% sure about the stability of the keep-alive mechanism and connection tear-down. Only tested on MacOS so far.

Smart cluster access solution tailored to VSHNs management of Kubernetes clusters over SSH jumphosts.

Starts a socks5 proxy that automatically routes cluster domains of configured jumphosts.

## Usage

Setup [SSH Jumphost (sshop)](https://vshnwiki.atlassian.net/wiki/spaces/VT/pages/8291275/SSH+Jumphost+sshop).

Download a copy of https://git.vshn.net/vshn/openshift4-clusters/-/raw/main/domain_jumphost_mapping.json?ref_type=heads.

```sh
go run . domain_jumphost_mapping.json
```

Point your browser or `kubectl`/`oc` to `socks5h://localhost:12000`.
