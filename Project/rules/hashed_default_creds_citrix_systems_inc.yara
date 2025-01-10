/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_citrix_systems_inc
{
    meta:
        id = "7c2O3oti5oQoO7N2KKlFlK"
        fingerprint = "2214c4ec7ad430bd4af93ec7069edd3277210b72c531601b87e34d49ad27300a"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for citrix_systems_inc."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c6de76e9bc256d0e0fc81247abec81e7"
    $a1="c6de76e9bc256d0e0fc81247abec81e7"
    $a2="824973847639cb5a8ff529dd3f6454ff"
    $a3="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql323_hashed_default_creds_citrix_systems_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for citrix_systems_inc."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="021f7eab3c80ed4c"
    $a1="021f7eab3c80ed4c"
    $a2="737552877c625297"
    $a3="67457e226a1a15bd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql41_hashed_default_creds_citrix_systems_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for citrix_systems_inc."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*509C3BB9F0B491E8FBD7BFD9434B0BEC2AAB69DE"
    $a1="*509C3BB9F0B491E8FBD7BFD9434B0BEC2AAB69DE"
    $a2="*1277D7238CD54A118C48B8DD228CABBF89502878"
    $a3="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_md5_hashed_default_creds_citrix_systems_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for citrix_systems_inc."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}FZhR9s0DyCu6JFXbI4WZWQ=="
    $a1="{MD5}FZhR9s0DyCu6JFXbI4WZWQ=="
    $a2="{MD5}zZKiZTTbpIzXhc3MCz5r0Q=="
    $a3="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_sha1_hashed_default_creds_citrix_systems_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for citrix_systems_inc."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}Q/Opt0IsSSVkRvj1TNFUCly1Zrk="
    $a1="{SHA}Q/Opt0IsSSVkRvj1TNFUCly1Zrk="
    $a2="{SHA}GpNTFFea3+jcGNtq4eiuxN+UGpM="
    $a3="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule md5_hashed_default_creds_citrix_systems_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for citrix_systems_inc."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="159851f6cd03c82bba2455db23859959"
    $a1="159851f6cd03c82bba2455db23859959"
    $a2="cd92a26534dba48cd785cdcc0b3e6bd1"
    $a3="63a9f0ea7bb98050796b649e85481845"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_citrix_systems_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for citrix_systems_inc."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43f3a9b7422c49256446f8f54cd1540a5cb566b9"
    $a1="43f3a9b7422c49256446f8f54cd1540a5cb566b9"
    $a2="1a935314579adfe8dc18db6ae1e8aec4df941a93"
    $a3="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_citrix_systems_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for citrix_systems_inc."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="902fe947d27da3624192a838bf215458d068f4e5f05544e6a8c7132a50eb3e5cf7d5e180793ff9a5623216033052e4b5"
    $a1="902fe947d27da3624192a838bf215458d068f4e5f05544e6a8c7132a50eb3e5cf7d5e180793ff9a5623216033052e4b5"
    $a2="c8e4be78953b879b1ad771fbc1fb080dfbbdd939ddc1829eb84d1a02bd2f1531b63ab70ec8b37edc6d3107e78157387a"
    $a3="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_citrix_systems_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for citrix_systems_inc."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ed339d5347bb8c7d342b3f9802521583da728cbe057e835242d9183a"
    $a1="ed339d5347bb8c7d342b3f9802521583da728cbe057e835242d9183a"
    $a2="9132ec183bfa4ac985230f71f349d6864935ce6dc02d808a697886a6"
    $a3="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_citrix_systems_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for citrix_systems_inc."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bedbc4b2ce194d741691fe6693e3dcfb7d3d64d3cfbcbbbba0efb1059891d16f7eaa8b07c17b1a74b08ee7d67e8ea88ac4b8c9d3beff5efc32845c6574202dae"
    $a1="bedbc4b2ce194d741691fe6693e3dcfb7d3d64d3cfbcbbbba0efb1059891d16f7eaa8b07c17b1a74b08ee7d67e8ea88ac4b8c9d3beff5efc32845c6574202dae"
    $a2="8fa46b8c73e1d37a5c0caeb40bbd4fec341988ffe54af0996ff59929b49fd88246f2c650c0e5e5ae8a55f1771a4c22aca3dfd06ead066318ae33cd893aaccae1"
    $a3="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_citrix_systems_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for citrix_systems_inc."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8dc07533fd6d3110d1b82de06289c52d8190c1ad19b2d58f4ea70f06da0ae27a"
    $a1="8dc07533fd6d3110d1b82de06289c52d8190c1ad19b2d58f4ea70f06da0ae27a"
    $a2="799824ba3560d3955f302c392de50e2232991ffaeca6f24200cf46571b523489"
    $a3="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_citrix_systems_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for citrix_systems_inc."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="87485c52e958804aa7ef2a32b168684cb739f179ad43d0d6e4ae42f8042abcd92f32cd52d9df5c0468960d62aac79a2f0e67aab1c88b207e0e1f4285244dc10c"
    $a1="87485c52e958804aa7ef2a32b168684cb739f179ad43d0d6e4ae42f8042abcd92f32cd52d9df5c0468960d62aac79a2f0e67aab1c88b207e0e1f4285244dc10c"
    $a2="d651a36187b6d01a9812213aa56682d60e1895af80b9f596d1e7167139a4c66564a1fd35fa236312ab6a961353456e6953b3409da643b384192b3156e75ee37a"
    $a3="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_citrix_systems_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for citrix_systems_inc."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fe66151dc72f3161b43d055f19b17cff31c8b1da3c4c5acb9935cea25186f1c7"
    $a1="fe66151dc72f3161b43d055f19b17cff31c8b1da3c4c5acb9935cea25186f1c7"
    $a2="135184fa03c0249f93e3c035457f986f887f294798f57efb63ff46391264cfa6"
    $a3="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_citrix_systems_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for citrix_systems_inc."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4cd430d5d60608b6185efd719ea4efe025da091cdc0cd318455c9e7b"
    $a1="4cd430d5d60608b6185efd719ea4efe025da091cdc0cd318455c9e7b"
    $a2="2d7977d8fd31d546485017eb23167a05cf59158ef4cd41100674f685"
    $a3="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_citrix_systems_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for citrix_systems_inc."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fecb449b8522288bc1c594c0198296ff5a40238927f24ceed09a30ec3ca70b15"
    $a1="fecb449b8522288bc1c594c0198296ff5a40238927f24ceed09a30ec3ca70b15"
    $a2="b3ba2f1db8eefecca5a701886790253b5cd6d23bf6533b8d070e1663282cccf2"
    $a3="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_citrix_systems_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for citrix_systems_inc."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4a83d5df66225bc42aa9b38e4f811f52ea721eab29d061fa0abccabccdf98075de97720f5796bc86f2986a7161b2e80b"
    $a1="4a83d5df66225bc42aa9b38e4f811f52ea721eab29d061fa0abccabccdf98075de97720f5796bc86f2986a7161b2e80b"
    $a2="6f43dcbffa37b4eb4769c3ff6461afb8a8b8e20a3fc49f8741a0ef3a563eef3456886461cfff76a5fd0735f80888c9eb"
    $a3="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_citrix_systems_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for citrix_systems_inc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f90b45460f217945bbd2b78fe34c39cf9c5de24dc4abf27a5a08bc5eff3249d5d443daed4f9eff467f24a6a81be472e5a93af31a6d820b49ec904fbb560e9086"
    $a1="f90b45460f217945bbd2b78fe34c39cf9c5de24dc4abf27a5a08bc5eff3249d5d443daed4f9eff467f24a6a81be472e5a93af31a6d820b49ec904fbb560e9086"
    $a2="5c28fa545a9f51d21f4ef7278184dc7e7809a64d9e9a19c98a6498480c38ea499828aa6553a6d8bf6c4dd82c9a72a19f45cc83b164860585c7facd622510561f"
    $a3="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_citrix_systems_inc
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for citrix_systems_inc."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bnNyb290"
    $a1="bnNyb290"
    $a2="cm9vdA=="
    $a3="cm9vdGFkbWlu"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

