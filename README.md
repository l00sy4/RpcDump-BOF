# RpcDump BOF

Beacon Object File that mimics Impacket's [rpcdump](https://github.com/fortra/impacket/blob/master/examples/rpcdump.py)

### Usage

The BOF takes three arguments:

- String representation of a protocol sequence
- String representation of the network address, in a format which corresponds with the protocol sequence (e.g. for `ncacn_ip_tcp` you need a four-octet IP or a host name)
- Flag indicating whether authentication should be used. If set, the BOF will use the security context of the calling thread. Otherwise the binding will be anonymous

### Example

```
rpcdump ncacn_ip_tcp localhost
```
