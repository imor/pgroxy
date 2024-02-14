A proxy to sniff postgres wire protocol traffic.

pgroxy sits between a client and a postgres server. It copies data between the client and the server while decoding the passing protocol packets and dumping them on stdout.

```
+--------+       +--------+        +----------+
| client | <---> | pgroxy |  <---> | postgres |
+--------+       +--------+        +----------+
                     |
                     V
                 +--------+
                 | stdout |
                 +--------+
```

Supported Messages (from https://www.postgresql.org/docs/current/protocol-message-formats.html):

- [x] AuthenticationOk
- [x] AuthenticationKerberosV5
- [x] AuthenticationCleartextPassword
- [x] AuthenticationMD5Password
- [x] AuthenticationGSS
- [x] AuthenticationGSSContinue
- [x] AuthenticationSSPI
- [x] AuthenticationSASL
- [x] AuthenticationSASLContinue
- [x] AuthenticationSASLFinal
- [x] BackendKeyData
- [ ] Bind
- [ ] BindComplete
- [x] CancelRequest
- [ ] Close
- [ ] CloseComplete
- [x] CommandComplete
- [x] CopyData
- [x] CopyDone
- [x] CopyFail
- [x] CopyInResponse
- [x] CopyOutResponse
- [x] CopyBothResponse
- [x] DataRow
- [ ] Describe
- [ ] EmptyQueryResponse
- [x] ErrorResponse
- [ ] Execute
- [ ] Flush
- [ ] FunctionCall
- [ ] FunctionCallResponse
- [x] GSSENCRequest
- [ ] GSSResponse
- [ ] NegotiateProtocolVersion
- [ ] NoData
- [ ] NoticeResponse
- [ ] NotificationResponse
- [ ] ParameterDescription
- [x] ParameterStatus
- [ ] Parse
- [ ] ParseComplete
- [ ] PasswordMessage
- [ ] PortalSuspended
- [x] Query
- [x] ReadyForQuery
- [x] RowDescription
- [x] SASLInitialResponse
- [x] SASLResponse
- [x] SSLRequest
- [x] StartupMessage
- [x] Sync
- [x] Terminate
