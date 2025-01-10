/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_mentec
{
    meta:
        id = "Pufjf9NzhyQV5lIRvSILG"
        fingerprint = "84a700c242c3bf70da17d7228b65fa3a7198ac09b7b7d71655b62253219bc636"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mentec."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2742d4e8bbcce1bd5df44a9cbe8f5849"
    $a1="caad23747fa118cba06e69eb3175c995"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_mentec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mentec."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7f4955d7267cdc74"
    $a1="39960d7c0dea21d2"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_mentec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mentec."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*ECFAC3D8F83CDB2DB1BECC629F8C957C86E0B340"
    $a1="*E022B9A5AA694399E5FDE97DB6444FF1C15CEBA8"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_mentec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mentec."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}OHBbpTLfEI1laJdFWByArA=="
    $a1="{MD5}FMtZOtXkIz2OkiGQATUIIQ=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_mentec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mentec."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}ZPJQnjgWzIbYBCm+QkpDG/8tnl0="
    $a1="{SHA}dy+1ldMlGAvZUqAbjvalfX0Py74="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_mentec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mentec."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="38705ba532df108d65689745581c80ac"
    $a1="14cb593ad5e4233d8e92219001350821"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_mentec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mentec."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="64f2509e3816cc86d80429be424a431bff2d9e5d"
    $a1="772fb595d325180bd952a01b8ef6a57d7d0fcbbe"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_mentec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mentec."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="14a80bcb82e085a28b4f555a824f607761893ccf140bd48b4226862f27ebeed742f8025e83dae5bf3078d228efa5e9ea"
    $a1="531a9ebc5892bffcfe960b8d9aaccedd5a769125093014991f9fc013aec215c82439570c5449c8afb6c3bfe80474ef72"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_mentec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mentec."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="54dad0bb829ff15eb1dc661e980f3b69d5791944eef9898fefd6e432"
    $a1="83081668bcb1f3b2d26b1f989303cd6fe0dfd7ff53045f92d55c9fd5"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_mentec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mentec."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f184565468795cb530cc19cb510a9fe6307017052152a44ba5ddbe5858f00fd38aec6b0e414831522d938263f83ec1c23d41b956b637387d8714ceb4f85e8c37"
    $a1="5cc61365b6a4bc604af55a81ac49d26c41a437b1f098d4c3085586cb586e5ab7ac8c691d09658c5c5b586f0a0b1bfcb883bf141ba2719f89c4518b672bf90c81"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_mentec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mentec."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d1def82c7182125d9573f0d32fbaf0a335471783984709da526a26d167ff532a"
    $a1="e425556fafa738b9df7b1fca2ceba5dc2c72ae03583c49aed001b2fbde89492b"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_mentec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mentec."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="886ea35aac3c6c96a8c6fc59ddc89cd44376cd0441cb4d4d1ae957858695280041298013612dafa508dbff7c29fe62f01ca072d6822b85d40d0200dfa1ad1a16"
    $a1="7c2fd17ca3ef62d2767d42b888c466048b1cd0228ff30e9f7fc76d70d504cf4463f63d2cd2f008c8a08ca3684a99211c41c9a8668f41e4d38b1581debc5a198c"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_mentec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mentec."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5fa108f7c1494550c600e2f174bce4371173840e5376c20e0cd127372806c46e"
    $a1="fa0c39a1d1860925ea0e571a3a74e81d041d322ff8e8aceb420fd52e756365c9"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_mentec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mentec."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43b7502f4464964c095a86aa5cd822719f9375c4967b762c48cc746d"
    $a1="deed3c24c32fd60689b89b4d782ed61b78d06248a38b1e3b1bece02f"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_mentec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mentec."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3d0c9a49420e92890a7a4f23faef8ed43c8be00cd272271d35ceb908580781a1"
    $a1="6260d281ebd3b464cd9afc57e15810877b0504cd8713f879e9f704619f47f754"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_mentec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mentec."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b11c68424e670d3d904291ce5b8321b3bc5b9dfd8f3376ac1d006d8b98f37e13099d2968705cc8c8ea37556c208e5ad3"
    $a1="9fd252aa83354cb14c673589fbebdcbb1c37853c189e06563b2f60377473a488a7015f7d60257aefba580ab60a9c53c4"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_mentec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mentec."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2091216f5c8bfc962206f9135031bc011f3831f3651b1827c20357f238312fedd50d3a05a4a62fb8a1afc8847a38f0912bcec151c5a2a2e1f4552911a80ca46c"
    $a1="7e522d39b21fa3d9b17108f158549cbe0761480df202ea73f3579c0751a9f7fe52b7c3d7cce6ff0604a33e85df3634b179d2fe665f131827602ef837e663aa27"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_mentec
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mentec."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="TUlDUk8="
    $a1="UlNY"
condition:
    ($a0 and $a1)
}

