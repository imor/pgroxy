A proxy to sniff postgres wire protocol traffic.

pgroxy sits between a client and a postgres server. It copies data between the client and the server while decoding the passing protocol packets and dumping them on stdout.

+--------+    +--------+    +----------+
| client | ⇄ | pgroxy | ⇄ | postgres |
+--------+    +--------+    +----------+
                  ↓
              +--------+
              | stdout |
              +--------+
