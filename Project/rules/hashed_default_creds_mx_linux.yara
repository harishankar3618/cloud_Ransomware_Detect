/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_mx_linux
{
    meta:
        id = "3Y9YgfIFXKh9xn1547vpmt"
        fingerprint = "520c7d35537cda98eb7f65664c80dbc3618f780af129b0d1fb1de62e4a34523b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="527c9c819b286efb8ec4ebb5b5ae71cf"
    $a1="527c9c819b286efb8ec4ebb5b5ae71cf"
    $a2="329153f560eb329c0e1deea55e88a1e9"
    $a3="329153f560eb329c0e1deea55e88a1e9"
    $a4="728a3edf824a80c984648faaf762e7ce"
    $a5="2e584618c0c086af05ace5bbd6465cc7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule mysql323_hashed_default_creds_mx_linux
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6d98684b668859ca"
    $a1="6d98684b668859ca"
    $a2="67457e226a1a15bd"
    $a3="67457e226a1a15bd"
    $a4="65a7e2964d411a0b"
    $a5="3e72b5160f5197eb"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule mysql41_hashed_default_creds_mx_linux
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*C142FB215B6E05B7C134B1A653AD4B455157FD79"
    $a1="*C142FB215B6E05B7C134B1A653AD4B455157FD79"
    $a2="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a3="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a4="*7696A148A42BA0F83F31613B2324447265D5A2ED"
    $a5="*A7AE60C580DE2418DC45F395674BE789771A530F"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule ldap_md5_hashed_default_creds_mx_linux
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}/gHOKn+6yPr67XyYKgTiKQ=="
    $a1="{MD5}/gHOKn+6yPr67XyYKgTiKQ=="
    $a2="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a3="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a4="{MD5}jFHoCiHbhyGd0o9PjGtjPA=="
    $a5="{MD5}ox5+nDj617LZR8ozWyMs7Q=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule ldap_sha1_hashed_default_creds_mx_linux
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}ieSV55Qc+eQOaYDRSha/AjzNTJE="
    $a1="{SHA}ieSV55Qc+eQOaYDRSha/AjzNTJE="
    $a2="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a3="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a4="{SHA}CY0sjqT3aTdu99rJcwIU39OIvAU="
    $a5="{SHA}7+PF5HxZWipHtgXTUTQDG2FI2Eg="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule md5_hashed_default_creds_mx_linux
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fe01ce2a7fbac8fafaed7c982a04e229"
    $a1="fe01ce2a7fbac8fafaed7c982a04e229"
    $a2="63a9f0ea7bb98050796b649e85481845"
    $a3="63a9f0ea7bb98050796b649e85481845"
    $a4="8c51e80a21db87219dd28f4f8c6b633c"
    $a5="a31e7e9c38fad7b2d947ca335b232ced"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_mx_linux
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="89e495e7941cf9e40e6980d14a16bf023ccd4c91"
    $a1="89e495e7941cf9e40e6980d14a16bf023ccd4c91"
    $a2="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a3="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a4="098d2c8ea4f769376ef7dac9730214dfd388bc05"
    $a5="efe3c5e47c595a2a47b605d35134031b6148d848"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_mx_linux
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="dcfe103c5c9ddd1e551a170e85534033a59c5c6f509b8c101ed489d70cdeadd2436ca8323fb4cd9e3699cdfa29ff1fb4"
    $a1="dcfe103c5c9ddd1e551a170e85534033a59c5c6f509b8c101ed489d70cdeadd2436ca8323fb4cd9e3699cdfa29ff1fb4"
    $a2="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a3="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a4="3d8157098553de71b2ca4d67e0935eacce3f7bfa57ea5e451df2d1405b433e98468a5808f572fd44fe2c6e17717cc4c1"
    $a5="32e6edcb41228ef83682775e647f5c81480459c69df4a4ac061cd1494636ee56951fc4276f25905c0e34f0c60a5cbe09"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_mx_linux
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8b1c1c1eae6c650485e77efbc336c5bfb84ffe0b0bea65610b721762"
    $a1="8b1c1c1eae6c650485e77efbc336c5bfb84ffe0b0bea65610b721762"
    $a2="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a3="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a4="5e8a73b456dfff165cdf5881ccbec3937383695456ee2a5b3a7da461"
    $a5="37f268bf04fe41f664b0d083000291579ff04ff05031ccf960be9d26"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_mx_linux
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="26c669cd0814ac40e5328752b21c4aa6450d16295e4eec30356a06a911c23983aaebe12d5da38eeebfc1b213be650498df8419194d5a26c7e0a50af156853c79"
    $a1="26c669cd0814ac40e5328752b21c4aa6450d16295e4eec30356a06a911c23983aaebe12d5da38eeebfc1b213be650498df8419194d5a26c7e0a50af156853c79"
    $a2="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a3="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a4="1e67764fa6fc82e0c945cf60bf82fa0b3340914df2abb8a8e76a5d6b80e88d9c2d395610113575250b075e6a1859a20d33eac0d8046bc43e720d3684c989031f"
    $a5="b9bc3e9a49d652c5f8ccab22293a3e4b6519db9ba713cedfde36e76f2bb383f8bf5ada5d09b0b0a275f66aa754c799fe9080125fbe2cbd0e7bb0f86029e6e5a5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_mx_linux
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2a97516c354b68848cdbd8f54a226a0a55b21ed138e207ad6c5cbb9c00aa5aea"
    $a1="2a97516c354b68848cdbd8f54a226a0a55b21ed138e207ad6c5cbb9c00aa5aea"
    $a2="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a3="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a4="dbf52493dd577628f395f00094f89a23c1b0f7df4ce66924eb5f53525d686886"
    $a5="854a910f6b22e3564adc9aabf03bdb6937a9dfac69b166896f710a14e8a169d0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_mx_linux
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ac6a680d94b3f2331f9a9e02397c14fa08e0e4f4c07527e311aa60c3753450f23b408af9b31491dbfad20171fb044544ad604dc5ad6bcb3a00818ec24ab19c00"
    $a1="ac6a680d94b3f2331f9a9e02397c14fa08e0e4f4c07527e311aa60c3753450f23b408af9b31491dbfad20171fb044544ad604dc5ad6bcb3a00818ec24ab19c00"
    $a2="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a3="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a4="56ceed7e63a70e54961e635f5d50915b522cfc98c2a21dc61a9548fbe7f5eb139d66d1bda40ff1033abfc796e53bf2dfa56aa00429d130ade11e268db3b3e08f"
    $a5="6ac142436fd99dcb9a7b944f295af7ba5026f6e8baab6d149820a4b9802b5939c97d0aad3083eb62cebb2983aafb98c743aa3390dc0d23d0a4719ae0b96d2f01"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_mx_linux
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="19ff8daf4d48897fed039c43198d3cc60ceb2fe012d36fd477829f3cf420252c"
    $a1="19ff8daf4d48897fed039c43198d3cc60ceb2fe012d36fd477829f3cf420252c"
    $a2="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a3="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a4="6625d441eb5ccdd1bf4b25d7d79f6981dcde2d8d1f129256aab66503a8de0246"
    $a5="809fde73e58d19e607c95bd63276904d24f7be93b948ebbba6f24f8f440bfa46"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_mx_linux
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="98cd35a76b3b20fb34d55f3fad8193de26eaa767e5ae294461864ba9"
    $a1="98cd35a76b3b20fb34d55f3fad8193de26eaa767e5ae294461864ba9"
    $a2="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a3="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a4="4208157f600102a9f99023f0df9cf2265d48cf1fd482813c309ae2bf"
    $a5="2d97a4f76c46889c5d04af8c69d26357a9165a8d4b54e6b6352bb143"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_mx_linux
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7f23e6ca181cc91d57245809edb1097a1f14ed011e4a9520a8dd10aa3ef82789"
    $a1="7f23e6ca181cc91d57245809edb1097a1f14ed011e4a9520a8dd10aa3ef82789"
    $a2="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a3="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a4="81e29bbbd09466b1ad43b87c8797f2bb61e5a4b3760c1842a4839fa295604aea"
    $a5="f7e49fe2d8f701cac98e7929e888ceda47160dfc155414c9c0012255192d1b68"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_mx_linux
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0d3250dddb782c53bc39b6c60f554b7818f7cb41099e8cc491b81441402bb89ebf6e9cdd6c615daafd91909d3ca30174"
    $a1="0d3250dddb782c53bc39b6c60f554b7818f7cb41099e8cc491b81441402bb89ebf6e9cdd6c615daafd91909d3ca30174"
    $a2="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a3="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a4="7d34b353bf14bef0cb10fa010c45c00b54f8679a491a90d2f1c060211b945d363b868c182065e020e48e8f7a385c41de"
    $a5="0371b75b7f47c0d4f5b1a536c9e9d0bd421a3bb2045fde76a3057d778ff6cc3127174762adc17c2045997a146859bfed"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_mx_linux
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a9210a3b1268ce3f2d9b5357dc79c1a4902cb5c5d7244589990263f1bac3d2678854031cc70444921fc6fb11ff9568dabc41a48b6bf3b808e84be58c0df4a881"
    $a1="a9210a3b1268ce3f2d9b5357dc79c1a4902cb5c5d7244589990263f1bac3d2678854031cc70444921fc6fb11ff9568dabc41a48b6bf3b808e84be58c0df4a881"
    $a2="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a3="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a4="bd4bab9e72dca06d431b09327dcd35568f0b825324198f0090d6df82b2fb575a183e2d6cf0d133e465f37817dd99c4768a3f03a66b525d39743ff45734762e21"
    $a5="1360fe78d0caf90da2808553794c97f248926298e69b4f0350d6c65f2bbd499afc33995b1aa16253525969fd28b09cfa2f2bc7b082eaff2393549939d4ceffa0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_mx_linux
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for mx_linux."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ZGVtbw=="
    $a1="ZGVtbw=="
    $a2="cm9vdA=="
    $a3="cm9vdA=="
    $a4="RnJlZTRNZQ=="
    $a5="ZnJlZTRtZQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

