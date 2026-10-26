use std::{
    fs::File,
    io::{BufReader, Write},
    path::Path,
    process::exit,
    sync::Arc,
};

use colored::Colorize;
use inquire::{Confirm, CustomType, Text};
use itertools::izip;
use log::{error, info};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SerialNumber,
};
use rustls::{crypto::aws_lc_rs::sign::any_supported_type, sign::CertifiedKey};
use time::{Duration, OffsetDateTime};

use crate::{CertificateGenParams, CustomCertResolver, Domain, utils::Config};

pub fn generate_ca(
    ca_common_name: &str,
    ca_lifetime_days: i64,
    cert_file_path: &str,
    cert_key_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Set up parameters for the CA
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc() + Duration::days(ca_lifetime_days);

    // Set the Distinguished Name and other fields to make the CA seem real
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, ca_common_name);
    dn.push(DnType::OrganizationName, "Sekai Injector Organization");
    dn.push(DnType::CountryName, "JP");
    params.distinguished_name = dn;
    params.use_authority_key_identifier_extension = true;
    params.serial_number = Some(SerialNumber::from(rand::random::<u64>()));

    // Generate a key pair and create the self-signed CA certificate
    let key_pair = KeyPair::generate()?;
    let ca_cert = params.self_signed(&key_pair)?;

    // Save the CA certificate and private key to files
    let mut cert_file = File::create(cert_file_path)?;
    cert_file.write_all(ca_cert.pem().as_bytes())?;

    let mut key_file = File::create(cert_key_path)?;
    key_file.write_all(key_pair.serialize_pem().as_bytes())?;

    Ok(())
}

pub fn new_self_signed_cert(
    cert_gen_params: CertificateGenParams,
) -> Result<(), Box<dyn std::error::Error>> {
    // Load the CA certificate and key
    let ca_cert_pem = std::fs::read_to_string(cert_gen_params.ca_cert_pem_path)?;
    let ca_key_pem = std::fs::read_to_string(cert_gen_params.ca_key_pem_path)?;
    let ca_cert_params = CertificateParams::from_ca_cert_pem(&ca_cert_pem)?;
    let ca_key = KeyPair::from_pem(&ca_key_pem)?;
    let ca_cert = ca_cert_params.self_signed(&ca_key)?;

    // Set up parameters for the server certificate
    let mut params = CertificateParams::new(vec![
        cert_gen_params.target_hostname.to_string(),
        cert_gen_params.target_ip.to_string(),
    ])?;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = OffsetDateTime::now_utc();
    params.not_after =
        OffsetDateTime::now_utc() + Duration::days(cert_gen_params.cert_lifetime_days);

    // Set the Distinguished Name
    let mut dn = DistinguishedName::new();
    dn.push(
        DnType::CommonName,
        cert_gen_params.distinguished_common_name,
    );
    params.distinguished_name = dn;

    // Generate a key pair and create the server certificate signed by the CA
    let key_pair = KeyPair::generate()?;
    let server_cert = params.signed_by(&key_pair, &ca_cert, &ca_key)?;

    // Save the server certificate and private key to files
    let mut cert_file = File::create(cert_gen_params.cert_file_out_path)?;
    cert_file.write_all(server_cert.pem().as_bytes())?;

    let mut key_file = File::create(cert_gen_params.cert_key_out_path)?;
    key_file.write_all(key_pair.serialize_pem().as_bytes())?;

    Ok(())
}

pub fn generate_certs_interactive(config_holder: &Config) {
    info!("{}\n{}", "\n!!! WARNING WARNING WARNING !!!".red(), "Never ever share any certificate or CA files with other people!\nIf you do, they could use it to compromise any devices you installed the certificate on!".yellow());
    info!("If you don't know what to put, just press enter for the defaults.");
    info!("Generating CA");
    let ca_common_name = Text::new("What should the CA be named?")
        .with_default("Sekai Injector CA")
        .prompt()
        .unwrap();

    let ca_lifetime_days: i64 = CustomType::new("How many days should the CA be valid?")
        .with_error_message("Please type a valid number")
        .with_default(3650)
        .prompt()
        .unwrap();

    let ca_cert_file_path = Text::new("Certificate path output")
        .with_default("ca_cert.pem")
        .prompt()
        .unwrap();

    let ca_cert_key_path = Text::new("Certificate path output")
        .with_default("ca_key.pem")
        .prompt()
        .unwrap();

    if !Path::new(&ca_cert_file_path).exists() && !Path::new(&ca_cert_key_path).exists() {
        match generate_ca(
            &ca_common_name,
            ca_lifetime_days,
            &ca_cert_file_path.clone(),
            &ca_cert_key_path.clone(),
        ) {
            Ok(_) => info!("Succesfully generated CA!"),
            Err(e) => {
                error!("There was an issue generating the CA: {e}");
                exit(1);
            }
        }
    } else {
        error!("Will not overwrite existing certificate!");
        exit(1);
    }

    info!("Signing new certificate(s) with CA");

    let (target_hostname, cert_file_out_paths, cert_key_out_paths) = {
        let auto_or_manual =
            Confirm::new("Generate certificates for all hostnames listed in the config?")
                .with_default(true)
                .prompt();

        let domain_info = config_holder.extract_domain_info();
        match auto_or_manual {
            Ok(true) => (domain_info.0, domain_info.1, domain_info.2),
            Ok(false) => (
                vec![
                    Text::new("Enter hostname to generate certificate for.")
                        .prompt()
                        .unwrap(),
                ],
                vec![
                    Text::new("Enter certificate file output file name.")
                        .prompt()
                        .unwrap(),
                ],
                vec![
                    Text::new("Enter certificate key output file name.")
                        .prompt()
                        .unwrap(),
                ],
            ),
            Err(_) => {
                error!("Error with prompt, defaulting to all hostnames.");
                (domain_info.0, domain_info.1, domain_info.2)
            }
        }
    };

    let target_ip = Text::new("What should the target IP be?")
        .with_default(&config_holder.target_ip)
        .prompt()
        .unwrap();

    let cert_lifetime_days: i64 =
        CustomType::new("How many days should the certificate(s) be valid?")
            .with_error_message("Please type a valid number")
            .with_default(3650)
            .prompt()
            .unwrap();

    let ca_cert_pem_path = Text::new("CA certificate path")
        .with_default("ca_cert.pem")
        .prompt()
        .unwrap();

    let ca_key_pem_path = Text::new("CA certificate path")
        .with_default("ca_key.pem")
        .prompt()
        .unwrap();

    for (hostname, cert_path, key_path) in
        izip!(&target_hostname, &cert_file_out_paths, &cert_key_out_paths)
    {
        match new_self_signed_cert(CertificateGenParams {
            ca_cert_pem_path: &ca_cert_pem_path,
            ca_key_pem_path: &ca_key_pem_path,
            target_hostname: hostname,
            target_ip: &target_ip,
            distinguished_common_name: hostname,
            cert_file_out_path: cert_path,
            cert_key_out_path: key_path,
            cert_lifetime_days,
        }) {
            Ok(_) => info!("Succesfully signed certificate with CA"),
            Err(e) => {
                error!("There was an issue signing the certificate: {e}");
                exit(1);
            }
        }
    }

    info!(
        "\nFinished generating CA and certificates. Remember to NEVER share the following files with anyone else: \n{}\n{}\n{:?}\n{:?}",
        ca_cert_file_path, ca_cert_key_path, cert_file_out_paths, cert_key_out_paths
    );
}

pub fn load_certs(domains: &Vec<Domain>) -> Result<CustomCertResolver, anyhow::Error> {
    let mut resolver = CustomCertResolver::new();

    for domain in domains {
        let cert_file = &mut BufReader::new(File::open(&domain.server_cert)?);
        let private_key_file = &mut BufReader::new(File::open(&domain.server_key)?);

        let certs = rustls_pemfile::certs(cert_file).collect::<Result<Vec<_>, _>>()?;

        let private_key = rustls_pemfile::private_key(private_key_file)?.unwrap();

        resolver.map.insert(
            domain.address.clone(),
            Arc::new(CertifiedKey {
                cert: certs,
                key: any_supported_type(&private_key).unwrap(),
                ocsp: None,
            }),
        );
    }

    Ok(resolver)
}

#[cfg(test)]
mod tests {
    use super::{generate_ca, new_self_signed_cert};
    use crate::CertificateGenParams;
    use openssl::{
        nid::Nid,
        pkey::PKey,
        x509::{X509NameRef, X509},
    };
    use std::{path::PathBuf, sync::OnceLock};

    trait X509NameSource {
        fn x509_name(&self) -> &X509NameRef;
    }

    impl X509NameSource for X509 {
        fn x509_name(&self) -> &X509NameRef {
            self.subject_name()
        }
    }

    impl X509NameSource for X509NameRef {
        fn x509_name(&self) -> &X509NameRef {
            self
        }
    }

    fn assert_nid_field(source: &impl X509NameSource, nid: Nid, expected: &str) {
        assert_eq!(
            source
                .x509_name()
                .entries_by_nid(nid)
                .next()
                .unwrap()
                .data()
                .to_string()
                .unwrap(),
            expected
        );
    }

    struct GeneratedCerts {
        _tempdir: tempfile::TempDir,
        ca_cert: PathBuf,
        server_cert: PathBuf,
        server_key: PathBuf,
    }

    fn generated_certs() -> &'static GeneratedCerts {
        static CERTS: OnceLock<GeneratedCerts> = OnceLock::new();

        CERTS.get_or_init(|| {
            let tempdir = tempfile::tempdir().unwrap();
            let ca_cert = tempdir.path().join("ca-cert.pem");
            let ca_key = tempdir.path().join("ca-key.pem");
            let server_cert = tempdir.path().join("cert.pem");
            let server_key = tempdir.path().join("cert-key.pem");

            generate_ca(
                "Sekai Injector Test CA",
                360,
                ca_cert.to_str().unwrap(),
                ca_key.to_str().unwrap(),
            )
            .unwrap();

            new_self_signed_cert(CertificateGenParams {
                ca_cert_pem_path: ca_cert.to_str().unwrap(),
                ca_key_pem_path: ca_key.to_str().unwrap(),
                target_hostname: "example.com",
                target_ip: "127.0.0.1",
                distinguished_common_name: "Sekai Injector Test",
                cert_file_out_path: server_cert.to_str().unwrap(),
                cert_key_out_path: server_key.to_str().unwrap(),
                cert_lifetime_days: 360,
            })
            .unwrap();

            GeneratedCerts {
                _tempdir: tempdir,
                ca_cert,
                server_cert,
                server_key,
            }
        })
    }

    fn load_ca_cert() -> X509 {
        X509::from_pem(&std::fs::read(&generated_certs().ca_cert).expect("Unable to read CA cert"))
            .unwrap()
    }

    fn load_server_cert() -> X509 {
        X509::from_pem(
            &std::fs::read(&generated_certs().server_cert).expect("Unable to read server cert"),
        )
        .unwrap()
    }

    #[test]
    fn ca_certificate_has_expected_subject() {
        let cert = load_ca_cert();

        assert_nid_field(&cert, Nid::COMMONNAME, "Sekai Injector Test CA");
        assert_nid_field(&cert, Nid::ORGANIZATIONNAME, "Sekai Injector Organization");
    }

    #[test]
    fn server_certificate_has_expected_issuer() {
        let cert = load_server_cert();

        assert_nid_field(
            cert.issuer_name(),
            Nid::COMMONNAME,
            "Sekai Injector Test CA",
        );
        assert_nid_field(
            cert.issuer_name(),
            Nid::ORGANIZATIONNAME,
            "Sekai Injector Organization",
        );
    }

    #[test]
    fn server_certificate_has_expected_subject_alt_names() {
        let cert = load_server_cert();
        let alt_names = cert.subject_alt_names().unwrap();

        assert!(alt_names
            .iter()
            .any(|name| name.dnsname() == Some("example.com")));
        assert!(alt_names
            .iter()
            .any(|name| name.ipaddress() == Some(&[127, 0, 0, 1])));
    }

    #[test]
    fn server_key_matches_certificate() {
        let cert = load_server_cert();
        let key_pem =
            std::fs::read(&generated_certs().server_key).expect("Unable to read server key");
        let private_key = PKey::private_key_from_pem(&key_pem).unwrap();

        assert!(cert.public_key().unwrap().public_eq(&private_key));
    }
}
