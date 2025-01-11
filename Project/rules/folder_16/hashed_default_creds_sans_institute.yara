/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_sans_institute
{
    meta:
        id = "2PcdCwxWP70KLJblglgwrz"
        fingerprint = "2d0d9f52496465df39d12b165fa212bf1f5f782f65722213e3b5accea4ff4295"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sans_institute."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5f9469a1db6c8f0dfd98af5c0768e0cd"
    $a1="a6ca6374172933fc9f172ed6df116e1b"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_sans_institute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sans_institute."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6e95496218c34e04"
    $a1="19bf00ef4bd5f74e"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_sans_institute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sans_institute."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*A8B0CB4DF573D591906E4A52F8F4F2EC24BF817E"
    $a1="*22297BD063213E030C25A9DE241EC59698517FBA"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_sans_institute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sans_institute."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}BfuRexZhwXp3qj3yTaKx2Q=="
    $a1="{MD5}+2mcxtAYYfPPSRozd+TX9Q=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_sans_institute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sans_institute."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}a4ucn6N3M2YJyUvrpuIinQjzGb8="
    $a1="{SHA}bvwy6LJESMTFYTNJSoL681uYyKw="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_sans_institute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sans_institute."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="05fb917b1661c17a77aa3df24da2b1d9"
    $a1="fb699cc6d01861f3cf491a3377e4d7f5"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_sans_institute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sans_institute."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6b8b9c9fa377336609c94beba6e2229d08f319bf"
    $a1="6efc32e8b24448c4c56133494a82faf35b98c8ac"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_sans_institute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sans_institute."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e159e949a4c01fd850b4692b2737df2f3a91e6bc3dda025a30b37eb0e8140cdd6e94b4819bc054f19ebf14f1606e0733"
    $a1="33d44ddc66107dd995f7f2699667933b9412f67e4ea6adaa58386bb10e39d479ecdbf37bcf0610d5fb7d9a394b051a57"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_sans_institute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sans_institute."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7b90c6d06f6b0f1ae25e5c4d260cc5445afe04fb8b24e5a2b7e1d39c"
    $a1="8324ffa4be68b833ba9ed6765d834f7a9daf0070c52812bcbef0ab70"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_sans_institute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sans_institute."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="18e8e49e8803e804454c42dacd1dbebfb1524a244b9fec3347fb1eeb9714ef0d0e813900f663c0398c6e4e344544ff396be81d92db3b782bc1ab349d16cf3e84"
    $a1="d280e89dc6f2d4ab38a13633da7cf38bf7adafbc7bf1941e95ec182f8d3e0b68a649ff732be7dee4e15851dd2d383c2339cf9f069490c38d804260213b04e84d"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_sans_institute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sans_institute."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b83d7514ba17c3f1156a2648c1a9d3d167143e695ad491e6197f88441c7a1e4a"
    $a1="5f11e0af908cf8ba7aa9501e715a10cb148f85d2e8ded6958039099f500221be"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_sans_institute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sans_institute."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fa015702a3f89c20b757ec3d291c9352b62de2260d6840e9d051a20a534f51333cb2ed82f52fe1dad27553498ee1658549ee85133ee7a6fc4bb86f55215e4aee"
    $a1="291d8d9b1a1ac34fea6b238960d0435362fe5f1fed20233a9a7db8a655da1137bb62fc2402bd5a520fc1cfd8085bc983b33c03982ce7e9cfe647352d12751210"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_sans_institute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sans_institute."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0863006984ebeb7bbbe932b2f0f7bd4e8d9fa28be7bb9574dc1503652f06232a"
    $a1="1de5b883995c7a5c6d50dca26924db50712eec67303f6fc4ef163b8724ff3784"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_sans_institute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sans_institute."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0a52500c57396156e9f1ad9202630b4f64e09a12b74b70a701c2fa55"
    $a1="0e1a1e3ffce2a4353395afc4f6aa6f54877bea6421e1592666552bd9"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_sans_institute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sans_institute."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="379f62a058f3d0222386d4474c65c91d16326bac4e85862667aa62efaab973d8"
    $a1="aa5d959f275209a04016ff431c70348dd1ea5ce398823794c559e5e74a44762d"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_sans_institute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sans_institute."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c4ecc5cbbefcac3adce0f0559989cf2a8a67c0151b7474ac5ee97bfbdc163437c9daf6eefa3da260100506b3ff6d81e8"
    $a1="39ffb7daeaa5c4497a5a8b9d2431e22e804519dc55e9ac48c52d5d469f6498b4f75b402518630856d0237136e39b3dfb"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_sans_institute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sans_institute."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c328185c10a15933f0f945703008a6faa123785ba8afb4fdeb0eb5305efad930673f0320cc9f6faaccfed74ff29e739bb07d75989439b5ce4f600bec653aea33"
    $a1="9ad45b0fdc9947153215a3a0f2edbf9246b41c44ba83125c149a2bd25b16e94ffa6bbe718ea10631723868db11c47d7059745306ec062b3360d9e98f39653a94"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_sans_institute
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for sans_institute."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c2Fuc2ZvcmVuc2ljcw=="
    $a1="Zm9yZW5zaWNz"
condition:
    ($a0 and $a1)
}

