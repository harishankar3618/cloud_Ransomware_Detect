/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_bosch
{
    meta:
        id = "3x2lGCC3t4XvOL5PdDg2sH"
        fingerprint = "16cffd8687009f22077cf4c920bd3bdbaa369045c4d08f50c806394ce2ad85fa"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bosch."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f07206c3869bda5acd38a3d923a95d2a"
    $a1="f07206c3869bda5acd38a3d923a95d2a"
    $a2="4f0ef98bb330fe5656d49369f5f9c5f5"
    $a3="4f0ef98bb330fe5656d49369f5f9c5f5"
    $a4="57d583aa46d571502aad4bb7aea09c70"
    $a5="57d583aa46d571502aad4bb7aea09c70"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule mysql323_hashed_default_creds_bosch
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bosch."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="75f8469b7e1d76be"
    $a1="75f8469b7e1d76be"
    $a2="3dc1531a5198dfe8"
    $a3="3dc1531a5198dfe8"
    $a4="1a486e7929011a28"
    $a5="1a486e7929011a28"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule mysql41_hashed_default_creds_bosch
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bosch."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*C80A94EF37B4CA1599BA47CC95530C43CACD7DA5"
    $a1="*C80A94EF37B4CA1599BA47CC95530C43CACD7DA5"
    $a2="*A9036AB3C885F8768D534E1666C52AF87780187F"
    $a3="*A9036AB3C885F8768D534E1666C52AF87780187F"
    $a4="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a5="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule ldap_md5_hashed_default_creds_bosch
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bosch."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}qqvw05lR8+bD6KeRHfUkwg=="
    $a1="{MD5}qqvw05lR8+bD6KeRHfUkwg=="
    $a2="{MD5}0NvpFQkdQAvY7n8n8HkTAw=="
    $a3="{MD5}0NvpFQkdQAvY7n8n8HkTAw=="
    $a4="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
    $a5="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule ldap_sha1_hashed_default_creds_bosch
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bosch."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}TPW8Wb7p4cRMYlS1+E5/BmvY5f4="
    $a1="{SHA}TPW8Wb7p4cRMYlS1+E5/BmvY5f4="
    $a2="{SHA}mKrbNwg+3dhVwn/syxXcjFsSf9A="
    $a3="{SHA}mKrbNwg+3dhVwn/syxXcjFsSf9A="
    $a4="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
    $a5="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule md5_hashed_default_creds_bosch
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bosch."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aaabf0d39951f3e6c3e8a7911df524c2"
    $a1="aaabf0d39951f3e6c3e8a7911df524c2"
    $a2="d0dbe915091d400bd8ee7f27f0791303"
    $a3="d0dbe915091d400bd8ee7f27f0791303"
    $a4="ee11cbb19052e40b07aac0ca060c23ee"
    $a5="ee11cbb19052e40b07aac0ca060c23ee"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_bosch
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bosch."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4cf5bc59bee9e1c44c6254b5f84e7f066bd8e5fe"
    $a1="4cf5bc59bee9e1c44c6254b5f84e7f066bd8e5fe"
    $a2="98aadb37083eddd855c27feccb15dc8c5b127fd0"
    $a3="98aadb37083eddd855c27feccb15dc8c5b127fd0"
    $a4="12dea96fec20593566ab75692c9949596833adc9"
    $a5="12dea96fec20593566ab75692c9949596833adc9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_bosch
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bosch."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="66e17cee68b63148b492c1e60cc3b9c85161eac639df6ccc878f251b056eb1a1994c6e81f1f6971a3ada23434c9c5ef2"
    $a1="66e17cee68b63148b492c1e60cc3b9c85161eac639df6ccc878f251b056eb1a1994c6e81f1f6971a3ada23434c9c5ef2"
    $a2="a54f652015d377c7580ae3f0c1de343e44e0cdcddfc6c9269ec63dfa2abd8e30bcdf66c4f75a554a328225be210cfc50"
    $a3="a54f652015d377c7580ae3f0c1de343e44e0cdcddfc6c9269ec63dfa2abd8e30bcdf66c4f75a554a328225be210cfc50"
    $a4="46cb0934bc1afda5a06031f9849b0281bb5cd03767e318e0a877c5a51962dbaa7d7f0dc146ce1bd85176d856907aa2c9"
    $a5="46cb0934bc1afda5a06031f9849b0281bb5cd03767e318e0a877c5a51962dbaa7d7f0dc146ce1bd85176d856907aa2c9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_bosch
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bosch."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3496179ea8bd6210252a6aeda9b8b598f0d4ef126328dca4a817d5f1"
    $a1="3496179ea8bd6210252a6aeda9b8b598f0d4ef126328dca4a817d5f1"
    $a2="834633ea2115ea629e018e15fb0c66803598397085b80d10d5b95f1f"
    $a3="834633ea2115ea629e018e15fb0c66803598397085b80d10d5b95f1f"
    $a4="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a5="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_bosch
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bosch."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b719607226d34094f53b043491697d98875096ff36bab4aab89da12850ac56195b183a0170976efbe29a6a4ddcc1f114b8f00154933ba6f766d82e5a63624eb4"
    $a1="b719607226d34094f53b043491697d98875096ff36bab4aab89da12850ac56195b183a0170976efbe29a6a4ddcc1f114b8f00154933ba6f766d82e5a63624eb4"
    $a2="d821a1ff45d3e9ca08019926356c25d13daf86abbf46717ca1eb6d14ebcae4fc795f29f6e8b559852129060a22b98c53d290d221c5e0ab34f29d5ba7d9c00e3d"
    $a3="d821a1ff45d3e9ca08019926356c25d13daf86abbf46717ca1eb6d14ebcae4fc795f29f6e8b559852129060a22b98c53d290d221c5e0ab34f29d5ba7d9c00e3d"
    $a4="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
    $a5="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_bosch
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bosch."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9df6b026a8c6c26e3c3acd2370a16e93fffdc0015ff5bd879218788025db0280"
    $a1="9df6b026a8c6c26e3c3acd2370a16e93fffdc0015ff5bd879218788025db0280"
    $a2="247610f4dedd4ab7247d07dbda19c81ca9817f85820742cad49d407ffae9e4ed"
    $a3="247610f4dedd4ab7247d07dbda19c81ca9817f85820742cad49d407ffae9e4ed"
    $a4="04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb"
    $a5="04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_bosch
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bosch."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9c0204c6a050d1a92ee3e332261796068dce670fd22f28ddc6e153e708948b30bf9d735ba1efd51e61b6876a2969ae32c3e3cb8fa1076a62c22165022d735d1d"
    $a1="9c0204c6a050d1a92ee3e332261796068dce670fd22f28ddc6e153e708948b30bf9d735ba1efd51e61b6876a2969ae32c3e3cb8fa1076a62c22165022d735d1d"
    $a2="3003335d76e570a38b6176f63ee02e53d2191e79f472f557b50a5e3cc31f03bd021d3a37db3435b7113d836395a83cfce1c4e75f35e36ab5a77fd78cf39ad2a4"
    $a3="3003335d76e570a38b6176f63ee02e53d2191e79f472f557b50a5e3cc31f03bd021d3a37db3435b7113d836395a83cfce1c4e75f35e36ab5a77fd78cf39ad2a4"
    $a4="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
    $a5="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_bosch
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bosch."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b07dad53a0d27d81641f20c700df09617c238f16d36bfda78b5a57d71414f486"
    $a1="b07dad53a0d27d81641f20c700df09617c238f16d36bfda78b5a57d71414f486"
    $a2="ecd5afadbdf81199e9e4d53396291eaf6b0af0ddf8b5b89546e101bd32a13c26"
    $a3="ecd5afadbdf81199e9e4d53396291eaf6b0af0ddf8b5b89546e101bd32a13c26"
    $a4="218d2ba09e825de93bfa9f18f753f55accda639fee17705d3ec19948b8f7a1d0"
    $a5="218d2ba09e825de93bfa9f18f753f55accda639fee17705d3ec19948b8f7a1d0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_bosch
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bosch."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="eca023569110ac72502e1e99d327f1ded5bf0e556747a883074b26bf"
    $a1="eca023569110ac72502e1e99d327f1ded5bf0e556747a883074b26bf"
    $a2="6fb76b0a78cc71b672bf52705613eda1fbc81fc48f52542445b7238f"
    $a3="6fb76b0a78cc71b672bf52705613eda1fbc81fc48f52542445b7238f"
    $a4="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a5="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_bosch
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bosch."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="63e5b5a4137cfa77cb9d10adae081d0df082a826d8441721460d5933f5800056"
    $a1="63e5b5a4137cfa77cb9d10adae081d0df082a826d8441721460d5933f5800056"
    $a2="c1d8ee2b15adbbb220ee2fcb332c02b40b614e9e8fe788cdb0932c9ebbf76833"
    $a3="c1d8ee2b15adbbb220ee2fcb332c02b40b614e9e8fe788cdb0932c9ebbf76833"
    $a4="8ac76453d769d4fd14b3f41ad4933f9bd64321972cd002de9b847e117435b08b"
    $a5="8ac76453d769d4fd14b3f41ad4933f9bd64321972cd002de9b847e117435b08b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_bosch
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bosch."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c81d6422d13cc3fb2ced709500d1acaed5dacc81f52c9adbcc20a6a8cbeaa38fa04aca067480c67e6ed909e5f56e618c"
    $a1="c81d6422d13cc3fb2ced709500d1acaed5dacc81f52c9adbcc20a6a8cbeaa38fa04aca067480c67e6ed909e5f56e618c"
    $a2="b761acdcf338cf377fbca40a79d0c14a0bc882efdc22b45d218cdc33be2d0ae25171e2f419f61f5191ec805afe5b27e0"
    $a3="b761acdcf338cf377fbca40a79d0c14a0bc882efdc22b45d218cdc33be2d0ae25171e2f419f61f5191ec805afe5b27e0"
    $a4="713d80421f781abcf2768f42fd1f17541c1fa03f68255d3d1fa4810590fdd77bb2a37d092f4b28fdfed380ba2dfafc7a"
    $a5="713d80421f781abcf2768f42fd1f17541c1fa03f68255d3d1fa4810590fdd77bb2a37d092f4b28fdfed380ba2dfafc7a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_bosch
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bosch."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cbab59d74fea767f62a9cac3851b832e01570b54280cbffa7bfe6f0f57352199adff8fe9530a129101047560f0992cc6990116bf8d38bcfb44f8ebd2bdf517fa"
    $a1="cbab59d74fea767f62a9cac3851b832e01570b54280cbffa7bfe6f0f57352199adff8fe9530a129101047560f0992cc6990116bf8d38bcfb44f8ebd2bdf517fa"
    $a2="c37063ea997ac32a465c2b99e95e846d4f3d419e692f4a7e9c0d312fdd9bda947070d7211350e8bf184fefc3f21ad487e6883f52f06b707513f9c486281df0d0"
    $a3="c37063ea997ac32a465c2b99e95e846d4f3d419e692f4a7e9c0d312fdd9bda947070d7211350e8bf184fefc3f21ad487e6883f52f06b707513f9c486281df0d0"
    $a4="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
    $a5="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_bosch
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for bosch."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c2VydmljZQ=="
    $a1="c2VydmljZQ=="
    $a2="bGl2ZQ=="
    $a3="bGl2ZQ=="
    $a4="dXNlcg=="
    $a5="dXNlcg=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

