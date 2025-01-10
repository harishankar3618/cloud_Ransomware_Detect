/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_schoolgirl
{
    meta:
        id = "6YN87krQQtWnaDjQBBpdtd"
        fingerprint = "bff4dcb096febab80f67554b97175ba2cd0dd291449833038c54419075e66b47"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schoolgirl."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c8ee7b9bbd1c844655162e0923b7fc6e"
    $a1="3b491869048dae930cef429847d758c7"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_schoolgirl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schoolgirl."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7aef2b3a221b4a59"
    $a1="7a83260a284b60a6"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_schoolgirl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schoolgirl."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*933665BF13DDD82C2DDE4CBCC399245E2F1FDDD1"
    $a1="*F68E81C01245D09016E2BA6AEC01580E638655B9"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_schoolgirl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schoolgirl."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}cCgYqClOnVVKyvYvrwpFYw=="
    $a1="{MD5}PPSbCWD7LvDqA9C5kYGWMA=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_schoolgirl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schoolgirl."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}iV2xznMVuN0U5+OF8ZoItADWyGU="
    $a1="{SHA}rJcJjtsuz8SemZZDsjaSxMHHDtM="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_schoolgirl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schoolgirl."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="702818a8294e9d554acaf62faf0a4563"
    $a1="3cf49b0960fb2ef0ea03d0b991819630"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_schoolgirl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schoolgirl."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="895db1ce7315b8dd14e7e385f19a08b400d6c865"
    $a1="ac97098edb2ecfc49e999643b23692c4c1c70ed3"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_schoolgirl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schoolgirl."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c2cb5263ddda99080396ff9ebd4c7bdd9fbda9dc80f4d2ca0ed6985e1f3ea176b5c40c5b4a027f0da5f9438c0d386c41"
    $a1="4eeda022ea59d7665ef784ad3bd557d36dc88c58a1e1dbbe4cb49081db444783318775baf0a11048eaeb9ae6d87bfac3"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_schoolgirl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schoolgirl."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ee3a18995cf8581d117bb2c92383711cdeb8d27e930601ebf01c03c0"
    $a1="243180e319b0d0752f8903f25dde3d9c99b7623d6b6358a21ab08bd0"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_schoolgirl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schoolgirl."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b79efb4932867d8e3d3822eeb101a8bd895a07d69c61786120e87a310d3f8ffd8896215facfc6a5aba7d3f7aa7325f98cf18183d43ddc5619a45e69b26344bf5"
    $a1="d35ec50a04360d3b42002a0449ddafaccac23660b071ccc561c299566bca611b630f215011eaffd2969539fc1619c661ed4d26573e83ce640bd5ac32ebc5b9ff"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_schoolgirl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schoolgirl."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aef0839575127e7bb3eb0c7c574ebc8d9a7163d9a4bca11fbfced360a82ecfd6"
    $a1="84c92d8abf326bdb52f1fc6cd6856c41ae9bc1ef4f6056c2672e3d9d301782e1"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_schoolgirl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schoolgirl."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1d38749b738890a960e3b46fe512e82e61827ec32aed422e1ca25655cb1298b005e255cab45e8eee64d66b87a313294d4d35b35dc5f90c89955d397540fdb550"
    $a1="506a74b9cb23fed6c4821f75e4cdf60e77520cbee30b5bfe7e675e6aaf2c78f2f90798463d18618dd520d89a3ee51d19ab3329078dc3e469ffffc372e9fb1269"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_schoolgirl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schoolgirl."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4757d31c39383a10c29ca84b4df9c9a3cacfec780bd1a52adc1619b97ddeb118"
    $a1="5bfd3bef7eb600a5ac9bd84c659ff3ab62e351360989d7929296c3e9caa5a911"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_schoolgirl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schoolgirl."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dd41a153dd3bed4ec9d8b93a70222a2bec446e6ccdfafa61b6ad7c85"
    $a1="3cb596c5ba498da9930fa77aa3b865f09af4498073f18cad99719f0a"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_schoolgirl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schoolgirl."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d1b199a6099a70b9db420c084a1f278c32cad3d52889228deace0349f270789c"
    $a1="c191e656a807424c3da184709fb6832f9d448e3082319c27148e1d4f55314be1"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_schoolgirl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schoolgirl."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ce3f0fc410e6ab5a43f9c591d50f3aa08e5992b758d9b29da399534f6d8b3c12d4b3e88a70e5c30aa51f72bb4daed377"
    $a1="02342ddfd0940940fd4077541960670dfff207e2a2bd3e7b9f5b41268d6359af14a1547e34d1adcc70b47851efe5cce4"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_schoolgirl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schoolgirl."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="763c330b6175d4a172a4e31d6a4eefc9efdeb6df149e90994ba6d7fd820dafabe2f543bda52f4f2248310b615f1132db8dea2d1d6e21bd5407ede1d6932ed5d0"
    $a1="fef5efd101af901ea0256757648220495152b887fb6517b44605a3b28afcffd622e7340ba8f4aa3a79aa6770955509485d21ce0e890256c40450cba6e18fdfe1"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_schoolgirl
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for schoolgirl."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aWNo"
    $a1="aGNp"
condition:
    ($a0 and $a1)
}

