/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_scylla
{
    meta:
        id = "4DhAepEHFqUCsOpUwHSOfK"
        fingerprint = "09870cb7bf9cdf2d43375161eb00f8a168f142588f63e1ff3068de8e4ee095e3"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for scylla."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e26f35f4ff58a7604fe2e559dd93770d"
    $a1="e26f35f4ff58a7604fe2e559dd93770d"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_scylla
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for scylla."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="07c5ae1670c40327"
    $a1="07c5ae1670c40327"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_scylla
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for scylla."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*D2FA81E53AC4D766516435829FB904E7E4B8E7E7"
    $a1="*D2FA81E53AC4D766516435829FB904E7E4B8E7E7"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_scylla
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for scylla."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}Ehxg3wwDCD0mk8JR8V/fsg=="
    $a1="{MD5}Ehxg3wwDCD0mk8JR8V/fsg=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_scylla
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for scylla."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}X2fmPufbH8210RPraggKJSlqi/o="
    $a1="{SHA}X2fmPufbH8210RPraggKJSlqi/o="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_scylla
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for scylla."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="121c60df0c03083d2693c251f15fdfb2"
    $a1="121c60df0c03083d2693c251f15fdfb2"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_scylla
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for scylla."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5f67e63ee7db1fcdb5d113eb6a080a25296a8bfa"
    $a1="5f67e63ee7db1fcdb5d113eb6a080a25296a8bfa"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_scylla
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for scylla."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="15810a9125e6ee1ca865e0ad2a608a15d9248dd796b8103d3e843f31e7a84245e5c80611824d29a5c40844165765dcaf"
    $a1="15810a9125e6ee1ca865e0ad2a608a15d9248dd796b8103d3e843f31e7a84245e5c80611824d29a5c40844165765dcaf"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_scylla
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for scylla."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="102cf74ee5d9504953de671e6e179b17a63f038dbb26d8abbee8adad"
    $a1="102cf74ee5d9504953de671e6e179b17a63f038dbb26d8abbee8adad"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_scylla
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for scylla."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ab6a34a451b061203fb9e7cbeae89f8b94c4d42ee38a88fbd6f5830dddf9efff3ace6d4fec6d9d6dd1596ce517a42fe06d0e4ab7e8c342391662871fbc5d9a02"
    $a1="ab6a34a451b061203fb9e7cbeae89f8b94c4d42ee38a88fbd6f5830dddf9efff3ace6d4fec6d9d6dd1596ce517a42fe06d0e4ab7e8c342391662871fbc5d9a02"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_scylla
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for scylla."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f1c6127b16ff422bfa09b98334abe44c5f88327e2a2185a2fe00ce26cdcf0075"
    $a1="f1c6127b16ff422bfa09b98334abe44c5f88327e2a2185a2fe00ce26cdcf0075"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_scylla
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for scylla."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="69b1dc5e659bf59b635bdd5f9bf05d6e67039444c0f8c0b9249dc4f6deb31d8413c6b49d169f37b1e12d0a61d1569aaf78a77e64e5718644fb74af25cb79a6c7"
    $a1="69b1dc5e659bf59b635bdd5f9bf05d6e67039444c0f8c0b9249dc4f6deb31d8413c6b49d169f37b1e12d0a61d1569aaf78a77e64e5718644fb74af25cb79a6c7"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_scylla
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for scylla."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="db7deb68b6318d965e54d001c61878dcceed4c85e77e3419d5a8ccf8899e6d57"
    $a1="db7deb68b6318d965e54d001c61878dcceed4c85e77e3419d5a8ccf8899e6d57"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_scylla
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for scylla."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b2ccf24fb37be226273b73eb1f23a77df667294c6bf5557597bd1e46"
    $a1="b2ccf24fb37be226273b73eb1f23a77df667294c6bf5557597bd1e46"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_scylla
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for scylla."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b53ecad66c4d9096207bec258188593b08e77b2705b73fea28184c9cfe93bce5"
    $a1="b53ecad66c4d9096207bec258188593b08e77b2705b73fea28184c9cfe93bce5"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_scylla
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for scylla."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6cbb41ff5703629f917e9ff62b7c3f058de68f79ebf16c52f3293d9b3e56a529af9910315b9557ca665d447616951048"
    $a1="6cbb41ff5703629f917e9ff62b7c3f058de68f79ebf16c52f3293d9b3e56a529af9910315b9557ca665d447616951048"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_scylla
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for scylla."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9e502029eed73376ac2a058f1f7cd7c44e6c0bf9a6a4448a1d0171336b48e96eadefe02cecef3d7d5bad793d29ba9a93d7d2ae7bd807695da47351486d6f3fe2"
    $a1="9e502029eed73376ac2a058f1f7cd7c44e6c0bf9a6a4448a1d0171336b48e96eadefe02cecef3d7d5bad793d29ba9a93d7d2ae7bd807695da47351486d6f3fe2"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_scylla
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for scylla."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="Y2Fzc2FuZHJh"
    $a1="Y2Fzc2FuZHJh"
condition:
    ($a0 and $a1)
}

