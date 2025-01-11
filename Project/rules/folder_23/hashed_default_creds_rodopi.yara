/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_rodopi
{
    meta:
        id = "44GyXe5WmH7MPbueu8Fhc2"
        fingerprint = "2936af38d3ccd53f01e85ab7e4cdefe98be117b4e98ac6963644f8a19a77bda0"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e2aea23ed4096af1f55ceb2b30c74802"
    $a1="e2aea23ed4096af1f55ceb2b30c74802"
    $a2="b4ae0d00cd8d8f612664e85400974938"
    $a3="b4ae0d00cd8d8f612664e85400974938"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql323_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="630dd577790e8ecb"
    $a1="630dd577790e8ecb"
    $a2="222fc8d705fd22eb"
    $a3="222fc8d705fd22eb"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql41_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*B2D5231B669B19CEE9E7BBE5523F984549EDFE99"
    $a1="*B2D5231B669B19CEE9E7BBE5523F984549EDFE99"
    $a2="*244912A25B6B47FBD75733351AF26E4E69570424"
    $a3="*244912A25B6B47FBD75733351AF26E4E69570424"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_md5_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}kNQrPed2FjZHBazP7WVCOw=="
    $a1="{MD5}kNQrPed2FjZHBazP7WVCOw=="
    $a2="{MD5}5TFDHjcfySHLy+P3Gf83qQ=="
    $a3="{MD5}5TFDHjcfySHLy+P3Gf83qQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_sha1_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}eS+ogzWtnudKxANHPNpQsjp7wRQ="
    $a1="{SHA}eS+ogzWtnudKxANHPNpQsjp7wRQ="
    $a2="{SHA}9OZfIFnvrtY3kzLX6QEVm6uu3hI="
    $a3="{SHA}9OZfIFnvrtY3kzLX6QEVm6uu3hI="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule md5_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="90d42b3de77616364705accfed65423b"
    $a1="90d42b3de77616364705accfed65423b"
    $a2="e531431e371fc921cbcbe3f719ff37a9"
    $a3="e531431e371fc921cbcbe3f719ff37a9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="792fa88335ad9ee74ac403473cda50b23a7bc114"
    $a1="792fa88335ad9ee74ac403473cda50b23a7bc114"
    $a2="f4e65f2059efaed6379332d7e901159babaede12"
    $a3="f4e65f2059efaed6379332d7e901159babaede12"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e765d85612d2fb2d4313c8bb5dcdb9947631ee8c0c30216ef7bf4fe8cc67cee8989362566781b0d58a923675b8109c96"
    $a1="e765d85612d2fb2d4313c8bb5dcdb9947631ee8c0c30216ef7bf4fe8cc67cee8989362566781b0d58a923675b8109c96"
    $a2="56832afc7613871a0b470754727a57305d89917876f207d3b6c44a256522ce97c8fca892667bc40ff7c304536f946e44"
    $a3="56832afc7613871a0b470754727a57305d89917876f207d3b6c44a256522ce97c8fca892667bc40ff7c304536f946e44"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b61bb0c069dad82f93a41b2a3a08c324f4583e629168858c11cc9e63"
    $a1="b61bb0c069dad82f93a41b2a3a08c324f4583e629168858c11cc9e63"
    $a2="e2da4d2c46076de30800a2777d7d7ae6be36b64e39246c345ff93676"
    $a3="e2da4d2c46076de30800a2777d7d7ae6be36b64e39246c345ff93676"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1a77f4fb127a0e45f099b42ff6ef8ba06b6d35cd400791009cacef09a7074f4398af0bfabddddd58d62d8565cb1e4007a3bf66c3eee1d0fa639c0269e81e26e3"
    $a1="1a77f4fb127a0e45f099b42ff6ef8ba06b6d35cd400791009cacef09a7074f4398af0bfabddddd58d62d8565cb1e4007a3bf66c3eee1d0fa639c0269e81e26e3"
    $a2="45b70e8b82b3db309e718914484c04eded60b99ea85bc1426c6184526cb9c2cd0246070620d6a618a476a624f9af7508ae94d132ecb16b6849cf875cfa6b5817"
    $a3="45b70e8b82b3db309e718914484c04eded60b99ea85bc1426c6184526cb9c2cd0246070620d6a618a476a624f9af7508ae94d132ecb16b6849cf875cfa6b5817"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eabb754e7d250aa2709317f63f1a62165a1f76990c87454f84e176927f459f4f"
    $a1="eabb754e7d250aa2709317f63f1a62165a1f76990c87454f84e176927f459f4f"
    $a2="88269a83b8b78a92b2b67e624dc05891c00f00ac8a6c59eace99e760bde49c10"
    $a3="88269a83b8b78a92b2b67e624dc05891c00f00ac8a6c59eace99e760bde49c10"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3e3aa1a799fce5de0e40487976697086347277090db2c17e2828b8620b4137b0c2a4c837ce5d6099b33a06fa3c775917a20fbeb9c3ec2c33f23479e3435fd2bb"
    $a1="3e3aa1a799fce5de0e40487976697086347277090db2c17e2828b8620b4137b0c2a4c837ce5d6099b33a06fa3c775917a20fbeb9c3ec2c33f23479e3435fd2bb"
    $a2="c02ba7538d011c7d7e4479de0cf678147d6f68297ece415c6947e5a067eb627d6383b0ecc4868442999598b18088435c4a4a3b82fa3697287c0910fa796b9f6c"
    $a3="c02ba7538d011c7d7e4479de0cf678147d6f68297ece415c6947e5a067eb627d6383b0ecc4868442999598b18088435c4a4a3b82fa3697287c0910fa796b9f6c"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b0d4332cbf6846f795f304eebf370186b213f70e864ce4d075aea05885aa5306"
    $a1="b0d4332cbf6846f795f304eebf370186b213f70e864ce4d075aea05885aa5306"
    $a2="6f7b1c074cdb9ff3de37be03ab3e1777231d2a9fcf5898033446f067d431ec4d"
    $a3="6f7b1c074cdb9ff3de37be03ab3e1777231d2a9fcf5898033446f067d431ec4d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6cfdba0f58bb5a719fd4f11e003d4526933495cb2cec499af55a0bbb"
    $a1="6cfdba0f58bb5a719fd4f11e003d4526933495cb2cec499af55a0bbb"
    $a2="ccc6df27da31287eb118c8af82dfd2020ad7c2fd4238abb5b2a15bc1"
    $a3="ccc6df27da31287eb118c8af82dfd2020ad7c2fd4238abb5b2a15bc1"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5cd025ec6ff48b39df1dcbdbc866d9fceec8b5db3fdfadf046e56d7e44a3bb23"
    $a1="5cd025ec6ff48b39df1dcbdbc866d9fceec8b5db3fdfadf046e56d7e44a3bb23"
    $a2="eef376bed892b16c8ee846e3cbee99856df0c1c68e5072405674ba82d259c5fe"
    $a3="eef376bed892b16c8ee846e3cbee99856df0c1c68e5072405674ba82d259c5fe"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a86f8458180791c36ef87727eecbe73b796df81714be28c23e73f6fa0808713c2b39b5e0699446205f3805ad17a84324"
    $a1="a86f8458180791c36ef87727eecbe73b796df81714be28c23e73f6fa0808713c2b39b5e0699446205f3805ad17a84324"
    $a2="c9c6d0620044eca7a8c12eb4054902606582b52b7e55990a65fe6944eef9a6a78b0cc9ef17084e927dc724310f422b8e"
    $a3="c9c6d0620044eca7a8c12eb4054902606582b52b7e55990a65fe6944eef9a6a78b0cc9ef17084e927dc724310f422b8e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5240ff6be65ec77463d5120cdfd9105ab0ec9c24a133a1c06c28d0266a4cf017c9d50806c57c7a71a00a2f345462be265d6c166d4b951c5ba8f6878912f1c7c3"
    $a1="5240ff6be65ec77463d5120cdfd9105ab0ec9c24a133a1c06c28d0266a4cf017c9d50806c57c7a71a00a2f345462be265d6c166d4b951c5ba8f6878912f1c7c3"
    $a2="c4588c2083bf49a593c9d78ac02db0191fb9cefc9eee6ad2fbd5fd42456b8949b95968208069d9006e2f62d2957d51ac66e6b058172f652d0e86c70f50065872"
    $a3="c4588c2083bf49a593c9d78ac02db0191fb9cefc9eee6ad2fbd5fd42456b8949b95968208069d9006e2f62d2957d51ac66e6b058172f652d0e86c70f50065872"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_rodopi
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for rodopi."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cm9kb3Bp"
    $a1="cm9kb3Bp"
    $a2="Um9kb3Bp"
    $a3="Um9kb3Bp"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

