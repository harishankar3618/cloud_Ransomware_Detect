/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_pollsafe
{
    meta:
        id = "2OoY5NRK2JEppJmYLEqL3N"
        fingerprint = "e46739306a6739e4eceafc192599b80b91706574a87aa3cc8e8ba2e8a6083c56"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pollsafe."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="75f67de9b91dce844c9783837761622b"
    $a1="793c81b3c6cf818021aa4e790fdf3387"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_pollsafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pollsafe."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0035428e228333db"
    $a1="442a89301c0f0a4a"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_pollsafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pollsafe."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*C2955866D10FEDA630ACFB0D0525215002F32BBC"
    $a1="*D15880C9288D08F7A173579F16DD5C7A63BE4A87"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_pollsafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pollsafe."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}NxsJ2TygHgmkL71aKkI/jg=="
    $a1="{MD5}yjm+HV3wtpE8IPBeoaxZuA=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_pollsafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pollsafe."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}PBxoiaPukrUOBmq5CZbqNPf4GJs="
    $a1="{SHA}DwSDflsVh0gL1d0lZdr3U8TcER8="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_pollsafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pollsafe."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="371b09d93ca01e09a42fbd5a2a423f8e"
    $a1="ca39be1d5df0b6913c20f05ea1ac59b8"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_pollsafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pollsafe."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3c1c6889a3ee92b50e066ab90996ea34f7f8189b"
    $a1="0f04837e5b1587480bd5dd2565daf753c4dc111f"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_pollsafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pollsafe."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="50aa1cd8d34b822285163a3c43124ba44a2ef47c10ce090fb42dc1aa556d861e75ddf343a13f0b630b6de4e78dc8ea07"
    $a1="00a996752c972e54a87c53b4427c0d714ed6dab7d232d9c62a679dfe92bbe69a3e3eaf593e1a78813da750aafba2a61b"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_pollsafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pollsafe."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6b8dff8ad3499917f23fa2ccd73bd2dc2bc23684150f64e30df2996f"
    $a1="0f23cb5454988be5a11c868d63c28415f3406865c7e537fbcb5900bb"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_pollsafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pollsafe."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6e67f8dbbbe2b9b302250b570cb2099e0f937f7139544800e84719e545fc6bb3b6f21d1eba6ee7fc6737535b500a0bf3752c12015b4e80454ceeaf4ba08897f1"
    $a1="2a61ef940744863cce48f228bbe836f0689fdd32615064befbf7f70fb42464f5ad7a5f2121159ada672875d3199c3d02874399986a5d4d24527193a0684de372"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_pollsafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pollsafe."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8f0ad38086075b37a535d141659ca0d0c98cee5987db82a325d3772e4dee2ee1"
    $a1="20bd5a6217e1d0b1a819794f3ff85c5f5d7380b6c6e734799e1be5d42b6b7cac"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_pollsafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pollsafe."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d147bb827edf0b78c11b39f69d871a5025db05a5ccf97d86fd967842068ade17f4b84c3b0a7740216c077675e73b54784bf9f421d3213fedf2d470a10d8ba6f5"
    $a1="bc06ca99fc895f454b021a1413c304f0b81f0b0a53285cc185f23d2eef4d6b31cf50b64fe8eceac3c5cfe729b7b1d1f0e6eef0ee08cff30788317adada1362f0"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_pollsafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pollsafe."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ecb70a7762ae4de51ade8691dbd617e30da39e05a2a739ff3a48aeeb524eed25"
    $a1="7e362c8c3cdff8ae96a6cab56544ca0692349dc9c88a54855f042df1fc9190b4"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_pollsafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pollsafe."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0ba629e1a8af632e9ff3f4fbc8b08b4fed373d45c212205070baa62f"
    $a1="4d3bd2f9b51c02b58bd735ce9668d87f7959bd1ed4d9cd068ecefce9"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_pollsafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pollsafe."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6dd7ef0fc7657da7b51d4aab5ff3850733c621ee52f6c81a92d554cc3f12cd2a"
    $a1="a01a25d4573adb2a60d5252e428f508fe5f23657d33c53a6800865b0c3cccbb9"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_pollsafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pollsafe."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a680be5b6406fe4cd964087f34e5858cd7e892d859118f84e27c4f88321f20e2700e666aa4359b61f74090fa998bfeea"
    $a1="259ef1392fbe43c5db3ee66e3762eb8dc6bd22fe098d270bca99b047c3a46239d3333b8125349b82897d25d587cd2360"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_pollsafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pollsafe."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4bc96e21751e17f915f76453074300345275b86a1ed9eb7d6f06a8f2a07596c0f35445b0bc90e5d52e6aac1635653d89d23b73120462822078794c226a59d07d"
    $a1="0f4637af3ed6d5e286930d703f36e5b2ed9f729ddfb02c2bcb8fd09f475689ec6d473a04ae6958f1440f323bc627a0447504505207d1cf81c2ef276f05b63d1e"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_pollsafe
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pollsafe."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="U01EUg=="
    $a1="U0VDT05EQVJZ"
condition:
    ($a0 and $a1)
}

