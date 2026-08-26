# Onion-service Nostr relay probe results

Snapshot taken 2026-08-25 with `scripts/onion_ws_probe.py` through a Tor
SOCKS5 proxy, 90 s timeout per step, one `REQ` for `kinds=[1] limit=2`.
Candidate list: every onion in
[0xtrr/onion-service-nostr-relays](https://github.com/0xtrr/onion-service-nostr-relays)
(25 relays). Tor rendezvous is flaky, so the timeouts and "general failure"
rows may pass on a retry; the 0x04 rows look genuinely dead.

## Working (6/25)

WebSocket upgrade succeeded, two `EVENT`s arrived, then `EOSE`.

| Relay | Time to EOSE |
|---|---|
| `ws://nostrwinemdptvqukjttinajfeedhf46hfd5bz2aj2q5uwp7zros3nad.onion` | 1.7 s |
| `ws://nerostrrgb5fhj6dnzhjbgmnkpy2berdlczh6tuh2jsqrjok3j4zoxid.onion` | 2.0 s |
| `ws://oxtrdevav64z64yb7x6rjg4ntzqjhedm5b5zjqulugknhzr46ny2qbad.onion` | 2.0 s |
| `ws://35vr3xigzjv2xyzfyif6o2gksmkioppy4rmwag7d4bqmwuccs2u4jaid.onion` | 4.9 s |
| `ws://7imqzy3ui3gpn4fdsvefaqjrs4zqvytm33h5jmcmzbfc2hmm4qhy2iad.onion` | 5.5 s |
| `ws://ollw6hjffdzgwonwlj2tfzza3uvzwxqfk6vgnvtdyqgptp2ojuqnt5id.onion` | 12.5 s |

## Failed (19/25)

| Relay | Failure |
|---|---|
| `ws://2jsnlhfnelig5acq6iacydmzdbdmg7xwunm4xl6qwbvzacw4lwrjmlyd.onion` | timed out |
| `ws://bitcoinr6de5lkvx4tpwdmzrdfdpla5sya2afwpcabjup2xpi5dulbad.onion` | host unreachable (onion service down, or its descriptor is missing) (0x04) |
| `ws://dmw5wbawyovz7fcahvguwkw4sknsqsalffwctioeoqkvvy7ygjbcuoad.onion` | host unreachable (onion service down, or its descriptor is missing) (0x04) |
| `ws://ghaven2hi3qn2riitw7ymaztdpztrvmm337e2pgkacfh3rnscaoxjoad.onion` | general failure (0x01) |
| `ws://girwot2koy3kvj6fk7oseoqazp5vwbeawocb3m27jcqtah65f2fkl3yd.onion` | host unreachable (onion service down, or its descriptor is missing) (0x04) |
| `ws://gnostr2jnapk72mnagq3cuykfon73temzp77hcbncn4silgt77boruid.onion` | timed out |
| `ws://gp5kiwqfw7t2fwb3rfts2aekoph4x7pj5pv65re2y6hzaujsxewanbqd.onion` | general failure (0x01) |
| `ws://nfrelay6saohkmipikquvrn6d64dzxivhmcdcj4d5i7wxis47xwsriyd.onion` | host unreachable (onion service down, or its descriptor is missing) (0x04) |
| `ws://nostrland2gdw7g3y77ctftovvil76vquipymo7tsctlxpiwknevzfid.onion` | host unreachable (onion service down, or its descriptor is missing) (0x04) |
| `ws://nostrnetl6yd5whkldj3vqsxyyaq3tkuspy23a3qgx7cdepb4564qgqd.onion` | host unreachable (onion service down, or its descriptor is missing) (0x04) |
| `ws://pemgkkqjqjde7y2emc2hpxocexugbixp42o4zymznil6zfegx5nfp4id.onion` | host unreachable (onion service down, or its descriptor is missing) (0x04) |
| `ws://pzfw4uteha62iwkzm3lycabk4pbtcr67cg5ymp5i3xwrpt3t24m6tzad.onion:81` | host unreachable (onion service down, or its descriptor is missing) (0x04) |
| `ws://sovbitgz5uqyh7jwcsudq4sspxlj4kbnurvd3xarkkx2use3k6rlibqd.onion` | host unreachable (onion service down, or its descriptor is missing) (0x04) |
| `ws://sovbitm2enxfr5ot6qscwy5ermdffbqscy66wirkbsigvcshumyzbbqd.onion` | host unreachable (onion service down, or its descriptor is missing) (0x04) |
| `wss://skzzn6cimfdv5e2phjc4yr5v7ikbxtn5f7dkwn5c7v47tduzlbosqmqd.onion` | host unreachable (onion service down, or its descriptor is missing) (0x04) |
| `ws://westbtcebhgi4ilxxziefho6bqu5lqwa5ncfjefnfebbhx2cwqx5knyd.onion` | host unreachable (onion service down, or its descriptor is missing) (0x04) |
| `ws://winefiltermhqixxzmnzxhrmaufpnfq3rmjcl6ei45iy4aidrngpsyid.onion` | host unreachable (onion service down, or its descriptor is missing) (0x04) |
| `ws://wineinboxkayswlofkugkjwhoyi744qvlzdxlmdvwe7cei2xxy4gc6ad.onion` | host unreachable (onion service down, or its descriptor is missing) (0x04) |
| `ws://xvgox2zzo7cfxcjrd2llrkthvjs5t7efoalu34s6lmkqhvzvrms6ipyd.onion` | host unreachable (onion service down, or its descriptor is missing) (0x04) |

## Raw probe output

```
ws://2jsnlhfnelig5acq6iacydmzdbdmg7xwunm4xl6qwbvzacw4lwrjmlyd.onion
  FAILED: timed out
ws://35vr3xigzjv2xyzfyif6o2gksmkioppy4rmwag7d4bqmwuccs2u4jaid.onion
  SOCKS5 CONNECT ok                        3.77s
  HTTP/1.1 101 Switching Protocols         4.47s
  sent REQ kinds=[1] limit=2
  EVENT  id=08dbce98f5410d74… kind=1
  EVENT  id=9fbde89d1dbf01ac… kind=1
  EOSE   after 2 events                   4.93s
  OK
ws://7imqzy3ui3gpn4fdsvefaqjrs4zqvytm33h5jmcmzbfc2hmm4qhy2iad.onion
  SOCKS5 CONNECT ok                        4.16s
  HTTP/1.1 101 Switching Protocols         4.80s
  sent REQ kinds=[1] limit=2
  EVENT  id=08dbce98f5410d74… kind=1
  EVENT  id=000000293c086ae9… kind=1
  EOSE   after 2 events                   5.48s
  OK
ws://bitcoinr6de5lkvx4tpwdmzrdfdpla5sya2afwpcabjup2xpi5dulbad.onion
  FAILED: SOCKS5 CONNECT failed: host unreachable (onion service down, or its descriptor is missing) (0x04)
ws://dmw5wbawyovz7fcahvguwkw4sknsqsalffwctioeoqkvvy7ygjbcuoad.onion
  FAILED: SOCKS5 CONNECT failed: host unreachable (onion service down, or its descriptor is missing) (0x04)
ws://ghaven2hi3qn2riitw7ymaztdpztrvmm337e2pgkacfh3rnscaoxjoad.onion
  FAILED: SOCKS5 CONNECT failed: general failure (0x01)
ws://girwot2koy3kvj6fk7oseoqazp5vwbeawocb3m27jcqtah65f2fkl3yd.onion
  FAILED: SOCKS5 CONNECT failed: host unreachable (onion service down, or its descriptor is missing) (0x04)
ws://gnostr2jnapk72mnagq3cuykfon73temzp77hcbncn4silgt77boruid.onion
  FAILED: timed out
ws://gp5kiwqfw7t2fwb3rfts2aekoph4x7pj5pv65re2y6hzaujsxewanbqd.onion
  FAILED: SOCKS5 CONNECT failed: general failure (0x01)
ws://nerostrrgb5fhj6dnzhjbgmnkpy2berdlczh6tuh2jsqrjok3j4zoxid.onion
  SOCKS5 CONNECT ok                        0.65s
  HTTP/1.1 101 Switching Protocols         1.18s
  sent REQ kinds=[1] limit=2
  EVENT  id=672861efbbaca8e7… kind=1
  EVENT  id=50fc8bd05b880ad7… kind=1
  EOSE   after 2 events                   1.97s
  OK
ws://nfrelay6saohkmipikquvrn6d64dzxivhmcdcj4d5i7wxis47xwsriyd.onion
  FAILED: SOCKS5 CONNECT failed: host unreachable (onion service down, or its descriptor is missing) (0x04)
ws://nostrland2gdw7g3y77ctftovvil76vquipymo7tsctlxpiwknevzfid.onion
  FAILED: SOCKS5 CONNECT failed: host unreachable (onion service down, or its descriptor is missing) (0x04)
ws://nostrnetl6yd5whkldj3vqsxyyaq3tkuspy23a3qgx7cdepb4564qgqd.onion
  FAILED: SOCKS5 CONNECT failed: host unreachable (onion service down, or its descriptor is missing) (0x04)
ws://nostrwinemdptvqukjttinajfeedhf46hfd5bz2aj2q5uwp7zros3nad.onion
  SOCKS5 CONNECT ok                        0.58s
  HTTP/1.1 101                             1.15s
  sent REQ kinds=[1] limit=2
  EVENT  id=d808bffe8251240c… kind=1
  EVENT  id=4a68846509ce9104… kind=1
  EOSE   after 2 events                   1.74s
  OK
ws://ollw6hjffdzgwonwlj2tfzza3uvzwxqfk6vgnvtdyqgptp2ojuqnt5id.onion
  SOCKS5 CONNECT ok                       11.20s
  HTTP/1.1 101 Switching Protocols        11.84s
  sent REQ kinds=[1] limit=2
  EVENT  id=0000e5eb2ea9b8f9… kind=1
  EVENT  id=0000ed5a7c26f912… kind=1
  EOSE   after 2 events                  12.48s
  OK
ws://oxtrdevav64z64yb7x6rjg4ntzqjhedm5b5zjqulugknhzr46ny2qbad.onion
  SOCKS5 CONNECT ok                        0.69s
  HTTP/1.1 101 Switching Protocols         1.42s
  sent REQ kinds=[1] limit=2
  EVENT  id=629faa618ededeee… kind=1
  EVENT  id=1873e6630a4f23e7… kind=1
  EOSE   after 2 events                   1.98s
  OK
ws://pemgkkqjqjde7y2emc2hpxocexugbixp42o4zymznil6zfegx5nfp4id.onion
  FAILED: SOCKS5 CONNECT failed: host unreachable (onion service down, or its descriptor is missing) (0x04)
ws://pzfw4uteha62iwkzm3lycabk4pbtcr67cg5ymp5i3xwrpt3t24m6tzad.onion:81
  FAILED: SOCKS5 CONNECT failed: host unreachable (onion service down, or its descriptor is missing) (0x04)
ws://sovbitgz5uqyh7jwcsudq4sspxlj4kbnurvd3xarkkx2use3k6rlibqd.onion
  FAILED: SOCKS5 CONNECT failed: host unreachable (onion service down, or its descriptor is missing) (0x04)
ws://sovbitm2enxfr5ot6qscwy5ermdffbqscy66wirkbsigvcshumyzbbqd.onion
  FAILED: SOCKS5 CONNECT failed: host unreachable (onion service down, or its descriptor is missing) (0x04)
wss://skzzn6cimfdv5e2phjc4yr5v7ikbxtn5f7dkwn5c7v47tduzlbosqmqd.onion
  FAILED: SOCKS5 CONNECT failed: host unreachable (onion service down, or its descriptor is missing) (0x04)
ws://westbtcebhgi4ilxxziefho6bqu5lqwa5ncfjefnfebbhx2cwqx5knyd.onion
  FAILED: SOCKS5 CONNECT failed: host unreachable (onion service down, or its descriptor is missing) (0x04)
ws://winefiltermhqixxzmnzxhrmaufpnfq3rmjcl6ei45iy4aidrngpsyid.onion
  FAILED: SOCKS5 CONNECT failed: host unreachable (onion service down, or its descriptor is missing) (0x04)
ws://wineinboxkayswlofkugkjwhoyi744qvlzdxlmdvwe7cei2xxy4gc6ad.onion
  FAILED: SOCKS5 CONNECT failed: host unreachable (onion service down, or its descriptor is missing) (0x04)
ws://xvgox2zzo7cfxcjrd2llrkthvjs5t7efoalu34s6lmkqhvzvrms6ipyd.onion
  FAILED: SOCKS5 CONNECT failed: host unreachable (onion service down, or its descriptor is missing) (0x04)
```
