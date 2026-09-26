//! Curated + embedded CA certs for Indian e-governance PDFs.
//!
//! Order: try embedded PEM first (offline), then optional network download.

use der::DecodePem;
use x509_cert::Certificate;

pub struct CuratedCa {
    pub issuer_match: &'static str,
    pub name: &'static str,
    /// Optional network URL (may be offline). Embedded PEM is preferred.
    pub url: Option<&'static str>,
    pub embedded_pem: Option<&'static str>,
}

// ---------------------------------------------------------------------------
// Embedded PEMs (SafeScrypt sub-CA → SafeScrypt CA 2014 → CCA India 2014)
// ---------------------------------------------------------------------------

const EMBEDDED_SUBCA_RCAI_CLASS2_2014: &str = r#"-----BEGIN CERTIFICATE-----
MIIFNzCCBB+gAwIBAgIFGeOxJAEwDQYJKoZIhvcNAQELBQAwgekxCzAJBgNVBAYT
AklOMSIwIAYDVQQKExlTaWZ5IFRlY2hub2xvZ2llcyBMaW1pdGVkMR0wGwYDVQQL
ExRDZXJ0aWZ5aW5nIEF1dGhvcml0eTEQMA4GA1UEERMHNjAwIDExMzETMBEGA1UE
CBMKVGFtaWwgTmFkdTE0MDIGA1UECRMrTm8uNCwgUmFqaXYgR2FuZGhpIFNhbGFp
LCBUYXJhbWFuaSwgQ2hlbm5haTEdMBsGA1UEMxMUSUkgRmxvb3IsIFRpZGVsIFBh
cmsxGzAZBgNVBAMTElNhZmVTY3J5cHQgQ0EgMjAxNDAeFw0xNDAzMDYwNDMwMDBa
Fw0yNDAzMDUwNDMwMDBaMHQxCzAJBgNVBAYTAklOMSIwIAYDVQQKExlTaWZ5IFRl
Y2hub2xvZ2llcyBMaW1pdGVkMQ8wDQYDVQQLEwZTdWItQ0ExMDAuBgNVBAMTJ1Nh
ZmVTY3J5cHQgc3ViLUNBIGZvciBSQ0FJIENsYXNzIDIgMjAxNDCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMdLWmI2QwuMUaDmmA9sA31KCi+x3jTbmvx6
+dPrqjeaN2/41l6XExq6i9g5AjK4XSwQM6pmtpi3VgUDQYud/v9my5BNasTc3GGV
KfsMMCMZaSxa9JFs6BCIztjOP6Q+nKamNqiIleGCH1EFt5dlRooks0XCtTvYmzaL
u72pY9/7w8yopPDDFRcAkiRP/+jEiMF3XrT+ksMkwAa2izFaWFQskxApPVZbJV00
7GL861c4vNeIIWMpaUPeJAWaRkC0RvuSdW19/dM3wA4pp45fwunlYao10hQwEgvN
9rvT44rFmT5UYsSfEOfOSinWiemObzOdQ+h8UtcbhCcHOlsoUp8CAwEAAaOCAVgw
ggFUMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEGMBMGA1UdIwQM
MAqACEw+jj2YAqV+MBEGA1UdDgQKBAhDDjdX6SfZCDArBgNVHREEJDAipCAwHjEc
MBoGA1UEAxMTU0FGRVNDUllQVE9OTElORV8xNTA/BgNVHR8EODA2MDSgMqAwhi5o
dHRwOi8vY3JsLnNhZmVzY3J5cHQuY29tL1NhZmVTY3J5cHRDQTIwMTQuY3JsMIGD
BggrBgEFBQcBAQR3MHUwSwYIKwYBBQUHMAKGP2h0dHBzOi8vd3d3LnNhZmVzY3J5
cHQuY29tL2RydXBhbC9kb3dubG9hZC9TYWZlU2NyeXB0Q0EyMDE0LmNlcjAmBggr
BgEFBQcwAYYaaHR0cDovL29jc3Auc2FmZXNjcnlwdC5jb20wEgYDVR0gBAswCTAH
BgVggmRkAjANBgkqhkiG9w0BAQsFAAOCAQEAj0h3yH3B0yBhS3Ye8CS1ZdPlpTUF
uyX3Fx7EEoM1TB8R1IznKBrlKCxRs9kZ2XX23Td0plriJgnATTEfAxZou4KwIs0c
AtWSSQpL3AquW4/PzuYTOVCUt9cAPXziqQISVoIqWcJjsg8fIXAffumLDHvZD/0q
Pq6xhZvFX1hfUv2wA6LSITB9VB4YzV5OyPm+SM1BFkq3HA07YY8rfLtCfDbF6y79
HV49bVESK0ZWNZqofMS9mvYM8xgAADpefe4ICh9TetGIOg3XL0vgX13MzLOy4xM/
tDkRPkNXuuUZ7n1jUwGkz8LJAOAc59zr2QI/DzAoEaeeBUrlNJZUCZoFAA==
-----END CERTIFICATE-----
"#;

const EMBEDDED_SAFESCRYPT_CA_2014: &str = r#"-----BEGIN CERTIFICATE-----
MIIEfDCCA2SgAwIBAgICJ7IwDQYJKoZIhvcNAQELBQAwOjELMAkGA1UEBhMCSU4x
EjAQBgNVBAoTCUluZGlhIFBLSTEXMBUGA1UEAxMOQ0NBIEluZGlhIDIwMTQwHhcN
MTQwMzA1MTEyOTIyWhcNMjQwMzA1MDYzMDAwWjCB6TELMAkGA1UEBhMCSU4xIjAg
BgNVBAoTGVNpZnkgVGVjaG5vbG9naWVzIExpbWl0ZWQxHTAbBgNVBAsTFENlcnRp
ZnlpbmcgQXV0aG9yaXR5MRAwDgYDVQQREwc2MDAgMTEzMRMwEQYDVQQIEwpUYW1p
bCBOYWR1MTQwMgYDVQQJEytOby40LCBSYWppdiBHYW5kaGkgU2FsYWksIFRhcmFt
YW5pLCBDaGVubmFpMR0wGwYDVQQzExRJSSBGbG9vciwgVGlkZWwgUGFyazEbMBkG
A1UEAxMSU2FmZVNjcnlwdCBDQSAyMDE0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEA1ItyK8oZbGY2Fy/xGL3yEhelRPVZjdY+tsihvRWhTNKIwarcecMt
H36qOKpw8vsjdd6kqZwWuPrvwjM9tKKvKw8/puL+kCAm4uXmrRcWG/yyQBghPc3m
/Sqy4/4t+HFIr/F0CHJX5a2mnw6hCLaj0FBQjSX4OAX3C2NsCAHFlhCA+5Ozfq+k
tNN0HPnzLmdN5Fudlws1FoCcmm8yl5cIylS6uZNxhJnrYmbuavJcM8BF1YJT3Xte
ITUed6UAWxxM9EJD3WL/iWja8fEoW46c62/vuaVAx7LMyB4f9Jk4i1zO8mAtzoCo
qm1ZXth3QyQSoksicjiIGH6oMYCoJEoVFwIDAQABo4HbMIHYMBIGA1UdEwEB/wQI
MAYBAf8CAQEwEQYDVR0OBAoECEw+jj2YAqV+MBIGA1UdIAQLMAkwBwYFYIJkZAIw
EwYDVR0jBAwwCoAIQrjFz22zV+EwLgYIKwYBBQUHAQEEIjAgMB4GCCsGAQUFBzAB
hhJodHRwOi8vb2N2cy5nb3YuaW4wDgYDVR0PAQH/BAQDAgEGMEYGA1UdHwQ/MD0w
O6A5oDeGNWh0dHA6Ly9jY2EuZ292LmluL3J3L3Jlc291cmNlcy9DQ0FJbmRpYTIw
MTRMYXRlc3QuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQBGtgAcDVM1lYRjAHxObKkv
daHTL0NxVsQj9dp1FbO/xpLralElHJIgHBMBge2VfzuzFRvG2Sthfv266e5eXJ3O
3SsHEh/rZOjfB945VSIaPMl8EZkdNkGZv+crVhC12uMx9XinbAHl2iCdxqHDAGM/
gUFzD1O+sLJIzh4Oup11dlNVAdsTAl2+itFnbjZ8KOhC8g42BcAW7Y6Hk1g814wN
IBq3Pj450PHWhBFjDdZzLZb7nX+5DhxWQYZtpE+yFQ0Y+oX9mo06Vraf46K6G40a
Zv4merE37P4B2owNHjY7lw1HvoqlxqJFX/H0iX2IxHxPBxA0k5s00c3jIlNfslW8
-----END CERTIFICATE-----
"#;

const EMBEDDED_CCA_INDIA_2014: &str = r#"-----BEGIN CERTIFICATE-----
MIIDIzCCAgugAwIBAgICJ60wDQYJKoZIhvcNAQELBQAwOjELMAkGA1UEBhMCSU4x
EjAQBgNVBAoTCUluZGlhIFBLSTEXMBUGA1UEAxMOQ0NBIEluZGlhIDIwMTQwHhcN
MTQwMzA1MTAxMDQ5WhcNMjQwMzA1MTAxMDQ5WjA6MQswCQYDVQQGEwJJTjESMBAG
A1UEChMJSW5kaWEgUEtJMRcwFQYDVQQDEw5DQ0EgSW5kaWEgMjAxNDCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAN7IUL2K/yINrn+sglna9CkJ1AVrbJYB
vsylsCF3vhStQC9kb7t4FwX7s+6AAMSakL5GUDJxVVNhMqf/2paerAzFACVNR1Ai
MLsG7ima4pCDhFn7t9052BQRbLBCPg4wekx6j+QULQFeW9ViLV7hjkEhKffeuoc3
YaDmkkPSmA2mz6QKbUWYUu4PqQPRCrkiDH0ikdqR9eyYhWyuI7Gm/pc0atYnp1sr
u3rtLCaLS0ST/N/ELDEUUY2wgxglgoqEEdMhSSBL1CzaA8Ck9PErpnqC7VL+sbSy
AKeJ9n56FttQzkwYjdOHMrgJRZaPb2i5VoVo1ZFkQF3ZKfiJ25VH5+8CAwEAAaMz
MDEwDwYDVR0TAQH/BAUwAwEB/zARBgNVHQ4ECgQIQrjFz22zV+EwCwYDVR0PBAQD
AgEGMA0GCSqGSIb3DQEBCwUAA4IBAQAdAUjv0myKyt8GC1niIZplrlksOWIR6yXL
g4BhFj4ziULxsGK4Jj0sIJGCkNJeHl+Ng9UlU5EI+r89DRdrGBTF/I+g3RHcViPt
One9xEgWRMRYtWD7QZe5FvoSSGkW9aV6D4iGLPBQML6FDUkQzW9CYDCFgGC2+awR
Mx61dQVXiFv3Nbkqa1Pejcel8NMAmxjfm5nZMd3Ft13hy3fNF6UzsOnBtMbyZWhS
8Koj2KFfSUGX+M/DS1TG2ZujwKKXCuKq7+67m0WF6zohoHJbqjkmKX34zkuFnoXa
Xco9NkOi0RBvLCiqR2lKfzLM7B69bje+z0EqnRNo5+s8PWSdy+xt
-----END CERTIFICATE-----
"#;

pub const CURATED_INDIAN_CAS: &[CuratedCa] = &[
    CuratedCa {
        issuer_match: "safescrypt sub-ca for rcai class 2",
        name: "SafeScrypt sub-CA for RCAI Class 2 2014 (embedded)",
        url: None,
        embedded_pem: Some(EMBEDDED_SUBCA_RCAI_CLASS2_2014),
    },
    CuratedCa {
        issuer_match: "safescrypt ca 2014",
        name: "SafeScrypt CA 2014 (embedded)",
        url: None,
        embedded_pem: Some(EMBEDDED_SAFESCRYPT_CA_2014),
    },
    CuratedCa {
        issuer_match: "cca india 2014",
        name: "CCA India 2014 (embedded)",
        url: None,
        embedded_pem: Some(EMBEDDED_CCA_INDIA_2014),
    },
    CuratedCa {
        issuer_match: "cca india",
        name: "CCA India 2014 (embedded)",
        url: None,
        embedded_pem: Some(EMBEDDED_CCA_INDIA_2014),
    },
];

#[derive(Debug, thiserror::Error)]
pub enum CuratedError {
    #[error("no curated CA matches issuer DN")]
    NoMatch,
    #[error("embedded certificate invalid: {0}")]
    EmbeddedInvalid(String),
    #[error("all curated sources failed: {0}")]
    AllFailed(String),
}

fn load_embedded(pem: &str) -> Result<Certificate, CuratedError> {
    Certificate::from_pem(pem).map_err(|e| CuratedError::EmbeddedInvalid(e.to_string()))
}

pub fn fetch_issuer_from_curated(issuer_dn: &str) -> Result<(Certificate, String), CuratedError> {
    let lower = issuer_dn.to_ascii_lowercase();
    let candidates: Vec<&CuratedCa> = CURATED_INDIAN_CAS
        .iter()
        .filter(|c| lower.contains(c.issuer_match))
        .collect();

    if candidates.is_empty() {
        return Err(CuratedError::NoMatch);
    }

    let mut errors = Vec::new();

    for entry in candidates {
        if let Some(pem) = entry.embedded_pem {
            match load_embedded(pem) {
                Ok(cert) => {
                    let msg = format!("issuer loaded from embedded store ({})", entry.name);
                    return Ok((cert, msg));
                }
                Err(e) => errors.push(e.to_string()),
            }
        }
    }

    Err(CuratedError::AllFailed(errors.join("; ")))
}
