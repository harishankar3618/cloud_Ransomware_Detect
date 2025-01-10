/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_psion_teklogix
{
    meta:
        id = "1QbEDv1VpkIdqd3tJ5ctTL"
        fingerprint = "74fdf1e5c047bbf969f45107f45ac541e65d3c12cfd279c55605c1fbf471fc32"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for psion_teklogix."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6ed11202d209f9d4bea955a3615225fc"
    $a1="1e1dd34b128de1968a44212e05d9e942"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_psion_teklogix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for psion_teklogix."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3c347c2b030525d0"
    $a1="441c54a74e618bc3"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_psion_teklogix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for psion_teklogix."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*72A9F66365ED9F7AC89749188A62191C600C74A1"
    $a1="*13F84CC62636F799FE455B4B4BD45DB6C02F599B"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_psion_teklogix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for psion_teklogix."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}vhIsUqiyXFXfa3rI0t0Z/Q=="
    $a1="{MD5}Q0mQyKJdK+lIY1Ya6YvWgg=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_psion_teklogix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for psion_teklogix."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}FWDvAwCfwvyp8zUkYFZhUomWVFQ="
    $a1="{SHA}W9zTwNTSSuPnGztFKgJMYyTH5Ls="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_psion_teklogix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for psion_teklogix."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="be122c52a8b25c55df6b7ac8d2dd19fd"
    $a1="434990c8a25d2be94863561ae98bd682"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_psion_teklogix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for psion_teklogix."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1560ef03009fc2fca9f335246056615289965454"
    $a1="5bdcd3c0d4d24ae3e71b3b452a024c6324c7e4bb"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_psion_teklogix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for psion_teklogix."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d046284a41bc3726c7c1c120e7b6fcf5e69f86b0dbbbc20ca3739fdff6eb25d488f92e7b21bacf0cd30700df8fa1093b"
    $a1="84525d116b92592940128eb5d0db333266515553da60abd89a95fccbd406721f6a85e174b3dcf570e33ec52ec0593dae"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_psion_teklogix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for psion_teklogix."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aca949cb9936d51537c18882dd2acf4ddee44b9eb29f06c1ab11b3af"
    $a1="b09ae657f9bb26f9e761879efebdb8dd5b3e72f8061271219b52cf72"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_psion_teklogix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for psion_teklogix."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cbc80bfdff84ddfa0c5f2ef379f6aae619146a605c221adb2ce518bbd82b54c33422daf3e2a6cccd06eaa5cee4f3527aadfe0a14c2451ae11252d3042bd2420c"
    $a1="a38db1acae90b2f7b58fa438fc027372acda829db34f46688bcc6cdd7546bf7bacc606b1d0f57da99b2f36ed695d5595576e1a54a90b8c33e2840c02c85fc58a"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_psion_teklogix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for psion_teklogix."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="40c7aa75d0a355a0a77bb75a29e2fbc394e2333ae0f8b87d5b6af6ddaef9d183"
    $a1="a18603086e5bdf9df88ccc9f5a083fed093e819976e87456b74dafcbd7011114"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_psion_teklogix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for psion_teklogix."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="24014add8e4640087f9d97ac298770a63ca6dec45da3bde89c8d30c0a642cc4ca7d8653213629f5fe18aba923fe50fc780837bdc7ea7aa7c26b390a91fbf6056"
    $a1="4ac3be53cae69554238d87f3c554d542c89f70b27ff17cbb11ecf83b5f1d6448738bf96c9682bf20a0b78963a532341834de37669223fbc41e1404bdc14efee2"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_psion_teklogix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for psion_teklogix."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b7533ef9de3f659591de74e063c9cb128b8e9282589662a260aae4716824a5be"
    $a1="1b5d83df688dce6fb84623f2ae9af4472e4c0649d6d761f1351fcad784546dd0"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_psion_teklogix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for psion_teklogix."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f56b9ec2386e48a5f1a1d4558ab54eabb28067caf56a1568937cf833"
    $a1="6e1ff225333ba37a13cbdb7ef72b8975a5e2e296698c06ea0fe65091"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_psion_teklogix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for psion_teklogix."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ff599989f6ba9eabd760527196977e94eb9b262040b7b9c29535913c9b6550d0"
    $a1="0c1e7a6a950cea0c33421085aa5ff978493162c6693e3e6caa2c73cf1e08c0d3"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_psion_teklogix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for psion_teklogix."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0f74e78e0782ee850f985fb8d2fc4ab5ebb8eab578d59ce41ffa74e614d9e0f4c0d86034130cb48e4c2fec27e07f1f89"
    $a1="562bcb29ac1fea5123ec2070cda76e28495e04f4fb24aee727eff58903d8661541d745bd906260fd72746d22aedb3a2f"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_psion_teklogix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for psion_teklogix."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ceb8d618f84e799be762a1732cbfe4bdd2d338ae28bda438059cdc4e93811dd2b9ef37769b455862b5ce075fdf979fa65ef65ac3aab2f9f2863b84efb9f4fffc"
    $a1="1fd0b56da32394c212a5aa993675d12eea0e0761d0662fa6ec068bd96830cd47cc914c0d8d12945f9fa346303aa91bbaf92d02874b27fd0369b36e6544e21c4c"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_psion_teklogix
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for psion_teklogix."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c3VwcG9ydA=="
    $a1="aDE3OTM1MA=="
condition:
    ($a0 and $a1)
}

