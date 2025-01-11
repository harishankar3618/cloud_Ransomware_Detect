/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_crt
{
    meta:
        id = "3GuV8Ro00q5XQHhWHJ9izh"
        fingerprint = "a8ce07733e105d473d1b2fb85f06074de5405fdcbb888807bd1f7ba6e203d760"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for crt."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2a38f10fd207668ca5ddb097fc95b9ce"
    $a1="b37a1ed2e1f2c0cd5077011c71d0c032"
condition:
    ($a0 and $a1)
}

rule mysql323_hashed_default_creds_crt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for crt."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="576a86ff3bd3e770"
    $a1="5208c28b2059486c"
condition:
    ($a0 and $a1)
}

rule mysql41_hashed_default_creds_crt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for crt."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*5A92E48C22EE4F815C488D4BD8366BFCC79E1549"
    $a1="*53249E3DEA3DE8798EA4522E8A145A9C9A37306E"
condition:
    ($a0 and $a1)
}

rule ldap_md5_hashed_default_creds_crt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for crt."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}li7xx1ULeQ2+IioB/RhxEQ=="
    $a1="{MD5}yvizaaZz+CUzPM9Z7Ne/Wg=="
condition:
    ($a0 and $a1)
}

rule ldap_sha1_hashed_default_creds_crt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for crt."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}PFo3dd5wd3sT5pDkrjosrN3/+iA="
    $a1="{SHA}3RyNwPF5qldOXFhzWt/2JCDSbHk="
condition:
    ($a0 and $a1)
}

rule md5_hashed_default_creds_crt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for crt."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="962ef1c7550b790dbe222a01fd187111"
    $a1="caf8b369a673f825333ccf59ecd7bf5a"
condition:
    ($a0 and $a1)
}

rule sha1_hashed_default_creds_crt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for crt."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3c5a3775de70777b13e690e4ae3a2cacddfffa20"
    $a1="dd1c8dc0f179aa574e5c58735adff62420d26c79"
condition:
    ($a0 and $a1)
}

rule sha384_hashed_default_creds_crt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for crt."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b6292b11d918f502260601e43758bee89204d42c3fdfdb63a4e05aab43447031cca7d8a40b117ba6d71a9d2cb07b19dd"
    $a1="bb4fa1e408c1d9a1b46af7126729b13cbd8a01e705bc6e26fc59b2a7de2e90b43991c792c4089438a4473bd5f6fa76cc"
condition:
    ($a0 and $a1)
}

rule sha224_hashed_default_creds_crt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for crt."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2a6a900c5d7d1e2af4bca459a8cb64fc291ab877662ce19321f5cb67"
    $a1="74cf1b20bb5eb3edd11ea546fb7877010f06424fac89d6d7a18f7337"
condition:
    ($a0 and $a1)
}

rule sha512_hashed_default_creds_crt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for crt."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b515a451324ff35cd55224f390cad6f1d9606c3678e164eeae19875b5444f9c3feefc792b02edb1b8c9b73e90964b484febc51650b2513aa4d99a48b5f0616a6"
    $a1="831baff160a608ef921ade3231a30d1f3d7a87f0919e20d84800be442f72e8b850e8d9af9b18e4f98f63f7d8594ebc04311d158159d6ea661f49c2a950504368"
condition:
    ($a0 and $a1)
}

rule sha256_hashed_default_creds_crt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for crt."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="282a07ca6622ee1a0905ece84b4fd7208efdb66576669ac05425462b446bee05"
    $a1="fd4d53fe3f8b48ad75c7284e049507af5ef766bbe95c63b027b639639b09ec06"
condition:
    ($a0 and $a1)
}

rule blake2b_hashed_default_creds_crt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for crt."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="089ad4a1f4542a5c787202aca7d2c866d642fea04b2095079516e854b279cc873c8954526ed54491e4af8ce4f9b9169b41128bb49969797c77fbeb99782b94de"
    $a1="09aa5f344a91d156cdeab4c5705a35bb5cec4eba1120b1e3d6041090c4703be0a7de8276e496824d0001b627732edd236a50023c658731bc0a201e792b15f16e"
condition:
    ($a0 and $a1)
}

rule blake2s_hashed_default_creds_crt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for crt."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c87f12938122af1870b0ebda9f9064d6d882e1a43fbfb90819ea4e287d9b8ebb"
    $a1="d2f099740be00c8dd0971a63f041892d448cd7d1e396b37ddaaa938278b530fc"
condition:
    ($a0 and $a1)
}

rule sha3_224_hashed_default_creds_crt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for crt."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0aa5e0e76168c09026162393243476ff90e02d498e8450d337dfa817"
    $a1="8ba39e850472e658663e9d702df887c9184787ee97dba5530e79c4fc"
condition:
    ($a0 and $a1)
}

rule sha3_256_hashed_default_creds_crt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for crt."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="680130426ecff5860a526f7ec156cb4f6fc41ddd0a3b271010753a0900610dff"
    $a1="7f73672fbffe44a89b1c6ab318ccadd20db8333e1ddc63d6fea69346b68ac6a7"
condition:
    ($a0 and $a1)
}

rule sha3_384_hashed_default_creds_crt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for crt."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4989b42988dfd06632c28aa8737106a17f7103a60a6ea68c6ce9719e33ca6f9dcd72eae891bbf2b6386e3681942e3bfc"
    $a1="b7b9ed8b52ae23af2a8623b24d27356b7056c9be59fd5ed63910b2c59149528462f6869bca3606cdb566b64984eea323"
condition:
    ($a0 and $a1)
}

rule sha3_512_hashed_default_creds_crt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for crt."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58857c71301907ac4669cf8f78d4c07e570e2e8257740d08ad7f5426a999546d54a1696ad6d70988982d840b4c78dd750f212c4dfd495e0a2ea2234359d3720a"
    $a1="c9fbb6fa8c4f01007aff7d72821cc14c4e4ee104f4d45ce27775279bdbb39e6bb1bd5b9e2984c08674541271398f1087e749138f3a9d47a20ffa480996d0e2cc"
condition:
    ($a0 and $a1)
}

rule base64_hashed_default_creds_crt
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for crt."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ZWdjcg=="
    $a1="ZXJnYw=="
condition:
    ($a0 and $a1)
}

