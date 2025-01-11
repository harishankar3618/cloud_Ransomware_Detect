/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_gitlab
{
    meta:
        id = "3t2rs6VNwys5DgEnOCyV7L"
        fingerprint = "e110876d94f4c6c4718b4cdcae82de2d9b1841eff3ebeb6392366ab3b630b680"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a98836559a04d1369a22055c3b889485"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="a98836559a04d1369a22055c3b889485"
    $a3="43a220431a6d2839cbb2eb21c95a0239"
    $a4="a98836559a04d1369a22055c3b889485"
    $a5="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule mysql323_hashed_default_creds_gitlab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0bb5920b208b560b"
    $a1="43e9a4ab75570f5b"
    $a2="0bb5920b208b560b"
    $a3="58656116549e2f6b"
    $a4="0bb5920b208b560b"
    $a5="67457e226a1a15bd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule mysql41_hashed_default_creds_gitlab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*99CF8099E82BA1429B9C084C9820A64848B9D2F3"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*99CF8099E82BA1429B9C084C9820A64848B9D2F3"
    $a3="*C261D162D699A1062FFA52AD73CC3F1BCE78FD63"
    $a4="*99CF8099E82BA1429B9C084C9820A64848B9D2F3"
    $a5="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule ldap_md5_hashed_default_creds_gitlab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}uIz2KzDs5DjBoZQnm1m7LA=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}uIz2KzDs5DjBoZQnm1m7LA=="
    $a3="{MD5}99qmWyqpYpC7R8TWjRH+ag=="
    $a4="{MD5}uIz2KzDs5DjBoZQnm1m7LA=="
    $a5="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule ldap_sha1_hashed_default_creds_gitlab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}GfUdYQxN/z4zRbcoFioD0Fe8HOE="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}GfUdYQxN/z4zRbcoFioD0Fe8HOE="
    $a3="{SHA}mZPA7iiCkgeMoaGNrVRaBmIlg/M="
    $a4="{SHA}GfUdYQxN/z4zRbcoFioD0Fe8HOE="
    $a5="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule md5_hashed_default_creds_gitlab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b88cf62b30ece438c1a194279b59bb2c"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="b88cf62b30ece438c1a194279b59bb2c"
    $a3="f7daa65b2aa96290bb47c4d68d11fe6a"
    $a4="b88cf62b30ece438c1a194279b59bb2c"
    $a5="63a9f0ea7bb98050796b649e85481845"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_gitlab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="19f51d610c4dff3e3345b728162a03d057bc1ce1"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="19f51d610c4dff3e3345b728162a03d057bc1ce1"
    $a3="9993c0ee288292078ca1a18dad545a06622583f3"
    $a4="19f51d610c4dff3e3345b728162a03d057bc1ce1"
    $a5="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_gitlab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="37aaec97cd830393f0ccae667decce32aac42a46f470198421982529ca2bb44863f0633fc90086471b22e2f117ed7088"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="37aaec97cd830393f0ccae667decce32aac42a46f470198421982529ca2bb44863f0633fc90086471b22e2f117ed7088"
    $a3="7a9bd2c97c0dac298d32249ecb1dbfa11a112206d1d4ca7019e8a949ee0b21ef5aa21fc1a6ace95894f0cac1bb1f9859"
    $a4="37aaec97cd830393f0ccae667decce32aac42a46f470198421982529ca2bb44863f0633fc90086471b22e2f117ed7088"
    $a5="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_gitlab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="282f187279d5fe05ed99480851f563e72ec328425848800fc9294330"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="282f187279d5fe05ed99480851f563e72ec328425848800fc9294330"
    $a3="14317ef3cef66033c1e77efbc868602a71e0a38fc7f160a850705edc"
    $a4="282f187279d5fe05ed99480851f563e72ec328425848800fc9294330"
    $a5="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_gitlab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e1a2969e95b496f90cef0812d38383c7b970e82df658c3937bebc0eab082fffa49a6abf0b954aac041efbb2dcfb49e35582d5975c2c98551ede1fc50ade2793c"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="e1a2969e95b496f90cef0812d38383c7b970e82df658c3937bebc0eab082fffa49a6abf0b954aac041efbb2dcfb49e35582d5975c2c98551ede1fc50ade2793c"
    $a3="45cb609b65c72bcd4b04bb464b4e8f607a494b266b875fc3dde1486c1c5353cf2c65d98b34cb2433b9a1e4c22dc73b257b8217a182a9185d6da0766fa9cebb93"
    $a4="e1a2969e95b496f90cef0812d38383c7b970e82df658c3937bebc0eab082fffa49a6abf0b954aac041efbb2dcfb49e35582d5975c2c98551ede1fc50ade2793c"
    $a5="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_gitlab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ae0b4ebbd85658b3dde6f9d8825495e65632cf5723ec4a72570e7137392290f4"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="ae0b4ebbd85658b3dde6f9d8825495e65632cf5723ec4a72570e7137392290f4"
    $a3="2e93f8045553c109d586f91d54e4902ff14dc793562a9d2ac2ca5bb86bce6ed9"
    $a4="ae0b4ebbd85658b3dde6f9d8825495e65632cf5723ec4a72570e7137392290f4"
    $a5="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_gitlab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1e7f380b70908b7318d4bb7ef77af23eb83e4c3cd555ff5fcd49e9c4a05e774c276a815fe8e3d076a708b40e01ca268432cdb2f9813c1ec40768590a7c60542a"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="1e7f380b70908b7318d4bb7ef77af23eb83e4c3cd555ff5fcd49e9c4a05e774c276a815fe8e3d076a708b40e01ca268432cdb2f9813c1ec40768590a7c60542a"
    $a3="0b0fca99fb86bd76323cc883535114175ff2e168d2676daa85475d50b78ec20826ef815b47247f1f023d49377f263e541de87865163ea6961ab6a184fcd485b8"
    $a4="1e7f380b70908b7318d4bb7ef77af23eb83e4c3cd555ff5fcd49e9c4a05e774c276a815fe8e3d076a708b40e01ca268432cdb2f9813c1ec40768590a7c60542a"
    $a5="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_gitlab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aea34b86bbccdd221949d7270ab77f350c1d9ad5103d86ecf3b1c6a41dfbaac5"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="aea34b86bbccdd221949d7270ab77f350c1d9ad5103d86ecf3b1c6a41dfbaac5"
    $a3="34f8088efcdb01c2ad09b5ddf0dab2db7815dcd85e41f470d6cd67643cfb7104"
    $a4="aea34b86bbccdd221949d7270ab77f350c1d9ad5103d86ecf3b1c6a41dfbaac5"
    $a5="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_gitlab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cac334731cde1dca8764170bd4bb168ce35a0f0b84a88936727eb279"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="cac334731cde1dca8764170bd4bb168ce35a0f0b84a88936727eb279"
    $a3="49982d908e2ed611f052ab311b4362b62d60c9fe9b146ea6054965be"
    $a4="cac334731cde1dca8764170bd4bb168ce35a0f0b84a88936727eb279"
    $a5="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_gitlab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7c007b61e8b67ec322918df9f14e516479352c936430baf4cc9e9f6ae441e9ff"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="7c007b61e8b67ec322918df9f14e516479352c936430baf4cc9e9f6ae441e9ff"
    $a3="a33d7fc424197e98a797d8ceb3cdfb47941e3f21d290ccaef47fe492130d9292"
    $a4="7c007b61e8b67ec322918df9f14e516479352c936430baf4cc9e9f6ae441e9ff"
    $a5="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_gitlab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1137f2dddf0376c98baf89b13bd4f659bf2b4b5a82efcf75efefdda10f385a63d7501b98d87a0edde0a38e5559acc859"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="1137f2dddf0376c98baf89b13bd4f659bf2b4b5a82efcf75efefdda10f385a63d7501b98d87a0edde0a38e5559acc859"
    $a3="14b1914cf42ec57ecd7f56c7d6fc406cfbd67e5f1028f4e72bf1f665bbb359f60931835b2ba21ec2d6d6008d7fe7cb4f"
    $a4="1137f2dddf0376c98baf89b13bd4f659bf2b4b5a82efcf75efefdda10f385a63d7501b98d87a0edde0a38e5559acc859"
    $a5="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_gitlab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="44e52253c0b6d0268921dff3f9c4937d4adf2a329cc81a4813dfccf646d7beb7198d19547e4cb0ead2d72b0d393afce77798a9d7604ae70cec25fb00fbc6bfc7"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="44e52253c0b6d0268921dff3f9c4937d4adf2a329cc81a4813dfccf646d7beb7198d19547e4cb0ead2d72b0d393afce77798a9d7604ae70cec25fb00fbc6bfc7"
    $a3="468d495158f47cd4f838375dd4aa880dbeb244392e74f58a32d82d88d0574df1ece01af93b6e5458bc62796981d13a4d0097e4b45bbbd2b6236234e8168aa5c7"
    $a4="44e52253c0b6d0268921dff3f9c4937d4adf2a329cc81a4813dfccf646d7beb7198d19547e4cb0ead2d72b0d393afce77798a9d7604ae70cec25fb00fbc6bfc7"
    $a5="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_gitlab
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for gitlab."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="NWl2ZUwhZmU="
    $a2="YWRtaW5AbG9jYWwuaG9zdA=="
    $a3="NWl2ZUwhZmU="
    $a4="cm9vdA=="
    $a5="NWl2ZUwhZmU="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

