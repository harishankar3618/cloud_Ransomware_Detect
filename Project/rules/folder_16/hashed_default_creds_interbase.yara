/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_interbase
{
    meta:
        id = "1XPxujVkZBrNuyW46nvzMI"
        fingerprint = "00051dfdde50386b975cda69d2b997c380379be4d05059687f9b28a52e22c323"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for interbase."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cdcc7a35d120c4f1c5da1422a4201708"
    $a1="c3d0be8b1416fb84e6cd4954431d5414"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_interbase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for interbase."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4825d68f2c211590"
    $a1="611eb17448acea4d"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_interbase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for interbase."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*E12CD91AC8FA1DC769505B9F283FAD0EC04AEE24"
    $a1="*B1705DCDDF6EA01DCC5EA75CCAAB259C3782EB1D"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_interbase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for interbase."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}q+bbTJ9UhPro158uhopnPA=="
    $a1="{MD5}SBHfLIO+5+46iDZAzE2Arw=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_interbase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for interbase."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}q0FUp8RR9W6bf/FTd1jd0MYZ+L4="
    $a1="{SHA}MlsyrGzcYHUCxFMjAPrdTToM3Bw="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_interbase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for interbase."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="abe6db4c9f5484fae8d79f2e868a673c"
    $a1="4811df2c83bee7ee3a883640cc4d80af"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_interbase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for interbase."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ab4154a7c451f56e9b7ff1537758ddd0c619f8be"
    $a1="325b32ac6cdc607502c4532300fadd4d3a0cdc1c"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_interbase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for interbase."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8dedd9fbb2b8711a25753f2faddfd4c7478f584e8f9ee89328f3fdfab770ee19abcc7fbae828335f73500137ee4091b9"
    $a1="253553fe01d9d5666fbd3cadacd95189085b9d922b25aa01fae15858a56db818e75f5afe1216b0bbffcc23bb3e28dc54"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_interbase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for interbase."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0a5fcaa8156df5fc8f006e239b44d01fd54862cee3056ef9ece150db"
    $a1="8b13d1565c9e9c0b74899415243e152d8caadf0f714b1f1f630fca2f"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_interbase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for interbase."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d5f92dcae90ec87247840df8a76a195aa1cd0f7fe996b1d79eb6f9da2294338a556b46cfd64e0fe3a00b71952e17a72880b01540485924150fbb5448098e6853"
    $a1="baefcd6c04eb788b2119ba9a1b6ee55bd9e0f872d2deb8eeef9723810f789774b2bf20e1d0d05d094e4b62a7b1062cc9e5c646128359ffecdd7b912eb1c38bdb"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_interbase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for interbase."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="48c5a1d217fe85082464d2ca1e90a16d15464fabe20f8610d79b63aa58797b9b"
    $a1="d42c104a926912d66fc148da987606648ae8e4ff88b21c810e51f8c47b3b7064"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_interbase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for interbase."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="95634d08635b26a78df2c5dc103556cc1a15ca5858c8bda7e04b16f9e68a8644eff5d2508be346a0c3ce742f064aa9abcc65e60302b589ecf88178ebcf9bd9ab"
    $a1="21121986da4c2c50df04d001ee5caab03158348b7874d5ab1743b423996756598585b35c5f127a8f6d7cd9414ee5a72d91d09bb0926ed81a82de548dd3e424a9"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_interbase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for interbase."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1afd6171483ae4dd7a2baf511850ebc9900b1adc9d8c37823a7a0650461a2c72"
    $a1="2c7e219e70e3709ea4da62059a7626ef9b1d375724dfd9edf713c3ae3107d225"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_interbase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for interbase."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="65a8b6efd24734f6e40cbfddad07491caab5ef3ec7f783df05aa1f7c"
    $a1="3eb683ffe6602c2cc920568281c655d9ea6f2b790d2633cf643f90f4"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_interbase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for interbase."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="479c8cc5b15e63edffa494719fb284525dcd351436ef9be5c6761eaead136c82"
    $a1="4bb99770fa21751eed6dd7496b1e3e1fc6e62b41ad403d90ca47f4feef023ffa"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_interbase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for interbase."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3b0be128d62f2800d7c12e8c90d361257b3df6638ab81a873d6c095a6357922cb910e3fb506739c6b812a564b49810da"
    $a1="5f14ad767216390bbea72abcc67d8bbb0005715e5993bc3ad6a15eef8fd93689fa551a434ee899fdc08ac3b6f7850083"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_interbase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for interbase."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bae826dd03f7c866258d7b93bde4be7ffe42d0039032436fa517abbe03da5babd149068e8a7f3f913a474a5c587ece5b7c005f7ad888b2c68e8651a7d40e518f"
    $a1="3e3ba9708644b3076b80bd3d7a687d3dae422148efb4a02aa7e577bdcba9bb28aaae2332ea3967a43f533ebc13b34062a11aa22eb17ac90e276f1a0a5dbddb17"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_interbase
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for interbase."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="U1lTREJB"
    $a1="bWFzdGVya2V5"
condition:
    ($a0 and $a1)
}

