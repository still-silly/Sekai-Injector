<div align="center">
   <img align="center" width="128px" src="https://files.catbox.moe/hvrqg1.png" />
	<h1 align="center"><b>Sekai Injector</b></h1>
	<p align="center">
		<b>A simple selective Rust proxy</b>
    <br />
  </p>
	
[![Build](https://github.com/timothyhay256/Sekai-Injector/actions/workflows/rust.yml/badge.svg)](https://github.com/timothyhay256/Sekai-Injector/actions/workflows/rust.yml)

</div>

### Sekai Injector
An simple Rust crate providing an lib/bin interface to selectively inject network resources into an application. Used by [MikuMikuLoader](https://github.com/timothyhay256/MikuMikuLoader).  

Provides an interface to generate CA/server certificates for your target domain(s), and a simple configuration file to configure injected resources. Supports multiple domains.  

### Demo video
This injects a simple modified scenario into Project Sekai, resulting in custom text.

https://github.com/user-attachments/assets/67990292-ff0b-4ed7-a8fb-09c073507db1

It uses the following injections.toml: 
```toml
map = [
    [
        "/3.5.1.0/bd3262f3-34ab-401d-bf97-be9f427484d5/android/event_story/event_whip_2024/scenario",
        "injections/whip-2024-scenario-override-encrypted",
        true,
    ],
]
```

Where `whip-2024-scenario-override-encrypted` was modified using [UABE](https://github.com/nesrak1/UABEA) and encrypted using [sssekai](https://github.com/mos9527/sssekai)

**This is currently being written for usage with Project Sekai: Colorful Stage. I am attempting to write it to be game-agnostic however, with all game-specific logic being restricted to config files. This should mean it can be used for whatever use needed.**

**It is currently very simple, and will hopefully evolve over time.**

## Usage
#### Config
Modify the config file to match your needs:

```toml
inject_resources = true                     # Is the program enabled?
target_ip = "192.168.86.183"                # What IP should the certificate be valid for?

[[domains]]
resource_config = "injections-ab.toml"      # Where should the injection map be loaded from for this domain?
address = "assetbundle.sekai-en.com"        # Host of this domain
server_cert = "server_cert_ab.pem"          # Server cert path
server_key = "server_key_ab.pem"            # Server key path
    
#[[domains]]                                # An additional domain
#resource_config = "injections-abinfo.toml"
#address = "assetbundle-info.sekai-en.com"
#server_cert = "server_cert_abinfo.pem"
#server_key = "server_key_abinfo.pem"

```

And modify injections-ab.toml:
```toml
map = [
    [
        "/path/on/origin/to/override",
        "file-to-serve-instead",
        true,
    ],
]
```

#### Generate CA and certificates
> [!CAUTION]
> NEVER share any .pem files that this program generates, or you risk opening yourself up to MITM attacks!
> Only ever install certificates that YOU generated, and revoke them if they are compromised!

To quickly and interactively generate all the required certificates, ensure `sekai-injector.toml` contains the host you intend to impersonate, and simply run `cargo run -- generate-certs`.  
Hit enter for each prompt to use the default options, which will generate 4 files:
 - ca_cert.pem: The CA certificate. This is what you install!
 - ca_key.pem: The CA key. This is used to sign the certificate, and should NEVER be shared!
 - server_cert.pem: The server certificate, signed by the CA for the domain you are impersonating.
 - server_key.pem: The server certificate key.

You can now install `ca_cert.pem` into your target device. On Android devices, unless the app trusts user CA certificates (most don't), you will need to root your device and use something like [Cert Fixer](https://github.com/pwnlogs/cert-fixer) to install it as a system CA.

You must then modify what IP address the target domain points to. On a rooted Android device, you could just modify `/etc/hosts`

After this, just run `cargo run -- start`! 
On Linux machines, you may need to either run the target binary as root, or run `sudo setcap 'cap_net_bind_service=+ep' target/debug/sekai-injector` to obtain the required permissions to serve on ports 443 and 80.
