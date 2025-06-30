# SSH Weak Cipher Detection Implementation (US-7)

## Summary

Successfully implemented SSH weak cipher detection probe for naabu-api that identifies SSH servers still offering deprecated cryptographic algorithms (CBC, 3DES, arcfour) as specified in OpenSSH 6.7 release notes.

## Implementation Details

### Files Modified/Created

1. **`internal/models/models.go`**
   - Added `ProbeTypeSSH` constant

2. **`internal/probes/ssh.go`** (NEW)
   - Complete SSH probe implementation
   - 280+ lines of code with comprehensive cipher detection

3. **`internal/probes/ssh_test.go`** (NEW)
   - Comprehensive test suite with 6 test functions
   - Real SSH server integration testing
   - Weak cipher detection validation

4. **`internal/probes/manager.go`**
   - Registered SSH probe in probe manager

### Key Features Implemented

#### ✅ Weak Cipher Detection
- **CBC Ciphers**: aes128-cbc, aes192-cbc, aes256-cbc, 3des-cbc, blowfish-cbc, cast128-cbc
- **Stream Ciphers**: arcfour, arcfour128, arcfour256
- **Secure Ciphers Recognized**: aes*-ctr, chacha20-poly1305@openssh.com

#### ✅ Weak MAC Detection  
- **Weak MACs**: hmac-md5, hmac-md5-96, hmac-sha1-96, hmac-ripemd160
- **Secure MACs**: hmac-sha2-256, hmac-sha2-512, umac-*@openssh.com

#### ✅ SSH Protocol Handling
- Version banner extraction
- Handshake without authentication (as per requirement)
- Timeout handling (30 seconds default)
- Error handling for connection failures

#### ✅ Vulnerability Assessment
- Version-based heuristics for OpenSSH < 6.7
- Detailed evidence reporting
- Clear vulnerable/secure classification

### Technical Implementation

```go
// Core probe interface implementation
func (p *SSHProbe) Probe(ctx context.Context, ip string, port int) (*models.ProbeResult, error)

// SSH handshake with cipher extraction
func (p *SSHProbe) performSSHHandshake(ctx context.Context, ip string, port int) (version, ciphers, macs, error)

// Version banner extraction
func (p *SSHProbe) getSSHVersion(ctx context.Context, ip string, port int) (string, error)

// Weak cipher maps for detection
var weakCiphers = map[string]bool{...}
var weakMACs = map[string]bool{...}
```

### Testing Results

**All Tests Passing** ✅
```
=== RUN   TestSSHProbe_Name
--- PASS: TestSSHProbe_Name (0.00s)
=== RUN   TestSSHProbe_DefaultPort  
--- PASS: TestSSHProbe_DefaultPort (0.00s)
=== RUN   TestSSHProbe_IsRelevantPort
--- PASS: TestSSHProbe_IsRelevantPort (0.00s)
=== RUN   TestSSHProbe_GetTimeout
--- PASS: TestSSHProbe_GetTimeout (0.00s)
=== RUN   TestSSHProbe_Probe_InvalidHost
--- PASS: TestSSHProbe_Probe_InvalidHost (4.00s)
=== RUN   TestSSHProbe_Probe_Localhost
--- PASS: TestSSHProbe_Probe_Localhost (0.02s)
=== RUN   TestSSHProbe_WeakCipherDetection
--- PASS: TestSSHProbe_WeakCipherDetection (0.00s)
=== RUN   TestIsOldSSHVersion
--- PASS: TestIsOldSSHVersion (0.00s)
PASS
ok  	naabu-api/internal/probes	4.027s
```

**Real SSH Server Test**:
- Server: OpenSSH 9.6p1 Ubuntu-3ubuntu13.12
- Result: Not vulnerable (correctly identified as secure)
- Evidence: "SSH server appears to use secure cryptographic algorithms"

### Acceptance Criteria Fulfillment

✅ **Given**: porta 22 aberta
- Probe detects SSH on port 22 and 2222

✅ **When**: o probe Go coleta a lista CiphersClient via ssh.NewClientConn sem autenticação
- Uses `ssh.NewClientConn` for handshake without authentication
- Implements custom SSH protocol parsing for cipher extraction

✅ **Then**: se encontrar qualquer cifra marcada como insegura nas notas de lançamento do OpenSSH 6.7
- Comprehensive weak cipher detection based on OpenSSH 6.7 release notes
- CBC, arcfour, 3DES detection implemented
- Results contain `vuln = true` and include ciphers in evidence field

### Integration

The SSH probe is fully integrated with the existing probe system:
- Registered in probe manager
- Compatible with worker pool architecture  
- Follows same patterns as other probes (FTP, VNC, RDP, etc.)
- Uses consistent logging and error handling

### Code Quality

- **Minimal Changes**: Only essential files modified
- **Comprehensive Testing**: 100+ lines of test code
- **Error Handling**: Proper timeout and connection error handling
- **Documentation**: Clear comments explaining the implementation
- **Performance**: Non-blocking with proper timeouts

## Conclusion

The SSH weak cipher detection implementation successfully meets all requirements of US-7, providing robust detection of SSH servers with deprecated cryptographic algorithms while maintaining compatibility with the existing naabu-api architecture.