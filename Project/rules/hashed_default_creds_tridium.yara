/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_tridium
{
    meta:
        id = "eKLerShLYCLTYuHSXJJDW"
        fingerprint = "f010f3f476e0a17f5bf2a87dab7491213913efe0aad6826e2c9dd52c9606141f"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tridium."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="26f088662b9ff69fd6d83b5a87c9d885"
    $a1="438100f2c044bd1e7a1eedfdc2bc1769"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_tridium
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tridium."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2a1b54f968e773ef"
    $a1="7994a26c00ff0902"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_tridium
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tridium."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*EAC2B0B2DC56B0D57601772C71F8F3B7335CA4BE"
    $a1="*0FBC1626ED81DEE89849955528F7DF54C50B2B9C"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_tridium
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tridium."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}jnqCSpMZaUWwf5aHyv9MVg=="
    $a1="{MD5}BOBQsAvgI0INWNuRMvaZpw=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_tridium
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tridium."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}Y32sv5BiXLVjZ4LkW7TXahFQIWU="
    $a1="{SHA}AhLCdvqMSAEhsXvRpSWb8/IVEfc="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_tridium
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tridium."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8e7a824a93196945b07f9687caff4c56"
    $a1="04e050b00be023420d58db9132f699a7"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_tridium
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tridium."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="637dacbf90625cb5636782e45bb4d76a11502165"
    $a1="0212c276fa8c480121b17bd1a5259bf3f21511f7"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_tridium
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tridium."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="19594d25947ecb7539be5f21a916b47e97b059b9fddc547cf9188be6ac809da480d66c4310e694e78ced79e95ac80c43"
    $a1="3d5ea073b8f423259a62eaf3f7d3dea51fbcb8073c90ddc9d9fb9910bad666d3e6c1b4ae19a683f2cb1e7085ab3b529a"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_tridium
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tridium."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f621e1bba28e252c957222ef06aa6c546521a05eff43fd4efb51b289"
    $a1="4e0bc09be74f54e27f0fbe9beec12d9e3019167cecb1938795e3ce75"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_tridium
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tridium."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cbe4316e5b19eeff6b70dd941271528e96e0d2f6fdd6f1847c459b863d50abe4b5c4942a01a97a62ac5508142951cf9988afac577a07843279b411e4d6b4eeef"
    $a1="f884b30ddbb9a9f85a5b2f8562b61650826e411f4430775b21f188e66782fbd9d0881e757be31a9fe21bf4b335f415301635af77cf69196232fe30e661f27027"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_tridium
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tridium."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3edec2353f5f1af480be3f5d3f66fe1035c422a32a9cbbfd74db8f9b99d93c88"
    $a1="1583c983c31d27b99e8ee57e9bb98fa2e6acf542664d0951c5edeabe0c751f01"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_tridium
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tridium."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="de8e56b27f82b0dfd3a14dd53d9955ed0d18de9ea0da32be30929d3392f81044677a63e4c5d196521409a34e492411db8d425acbd7fc50f20c7ecf185c9f2e2f"
    $a1="172dafad42f86f3cdd7a9b6c220309cd08e6953b11f1c3ec5c539943ff14a2ef48aff5a45ee85ec8190dbc8fbb2c681ebc056e8ee8c7c8b718c779a683e91837"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_tridium
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tridium."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e7330e433717456beab56ecf936bafb5650315d61f6b325b6bfc2b5b0b221649"
    $a1="3e242b5240a6098f0b674d3625f105b510f893f887ca6c75cb40f546119b20a2"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_tridium
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tridium."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="434701fea345d9081dd8591a39d63d2bc7403c8e80364e22df00cf68"
    $a1="83740f80c57d6a793a191408301af8141887c626539cb04c192af80a"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_tridium
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tridium."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f23c40ac856200d8b3b266d94b57e0bbfa752a6366363a5694dd11ba22b901b2"
    $a1="b41a9cc43c03074072ced4fade423c375ca7d953b4c5248065bb89f73640e628"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_tridium
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tridium."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="86e44d51fca52759c877d17f7d10d5680c75425b318960d3f052842a896fa676143b7ff82ccc006900d0a0070caab41b"
    $a1="d2b376342f8861c78ac61a7d2b22a517e60ff6ca82c577e2a6748ce51cf57fe67617d028f2853526d53a6a3e3b982db0"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_tridium
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tridium."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="53e9c267afc28f64a89d985fe614ea7f979e1ada72b47d68132b7da052727d5d96eb7285290ff0a0ffc3ccec4c5ce805d6672904e006b77d1c36fc4c5452c0d2"
    $a1="a68a3f4d23e4344236e5652dd765bcbfb6cb8dc22de73ca2c59f5d795a222c8db2e939aeb9bb5f10f74b34d1bd99f83dfb5e5e31b8b17dc9ab2b4c89df8f76b8"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_tridium
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for tridium."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dHJpZGl1bQ=="
    $a1="bmlhZ2FyYQ=="
condition:
    ($a0 and $a1)
}

