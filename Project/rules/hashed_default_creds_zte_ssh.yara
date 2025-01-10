/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_zte_ssh
{
    meta:
        id = "4lKlpQrfPu2e8BF3lPtZjq"
        fingerprint = "d2a1a6c251fac9240d1c74990977a1c8d4c1df8792216e6f6fac6d35ffb6b01b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="209c6174da490caeb422f3fa5a7ae634"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="016f2d39b6b86999e5d5dab89785ba16"
    $a3="016f2d39b6b86999e5d5dab89785ba16"
    $a4="60ee4c7cf22063506be0caf67a98b586"
    $a5="329153f560eb329c0e1deea55e88a1e9"
    $a6="469bd1289684cb7a6868b84042d44251"
    $a7="329153f560eb329c0e1deea55e88a1e9"
    $a8="57d583aa46d571502aad4bb7aea09c70"
    $a9="57d583aa46d571502aad4bb7aea09c70"
    $a10="fd31f5cebebeacfb0635b69f2ac9a63b"
    $a11="fd31f5cebebeacfb0635b69f2ac9a63b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule mysql323_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="43e9a4ab75570f5b"
    $a1="43e9a4ab75570f5b"
    $a2="077f60f349268295"
    $a3="077f60f349268295"
    $a4="7c07f8f57c0cc7df"
    $a5="67457e226a1a15bd"
    $a6="12e5e851114ffe5d"
    $a7="67457e226a1a15bd"
    $a8="1a486e7929011a28"
    $a9="1a486e7929011a28"
    $a10="023a6c872b7b546a"
    $a11="023a6c872b7b546a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule mysql41_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*771329914CC356A42E444A2DC393606CDE70921E"
    $a3="*771329914CC356A42E444A2DC393606CDE70921E"
    $a4="*24C38244E2BC651D19BF7EB85DF78DF5FB01AA93"
    $a5="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a6="*D2DFDFB8E2CCD75F076BF427D6E2DEB8C0B0D12D"
    $a7="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a8="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a9="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a10="*88D108DE81D643E6D250A0CE45BB50F96EBFDEF9"
    $a11="*88D108DE81D643E6D250A0CE45BB50F96EBFDEF9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule ldap_md5_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}7StcATnOyK0oc4KdwRF9UA=="
    $a3="{MD5}7StcATnOyK0oc4KdwRF9UA=="
    $a4="{MD5}z5ce4X1XH8H/pDamh2LDgQ=="
    $a5="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a6="{MD5}DsN3KoM27N3WtsYfAcBSRA=="
    $a7="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a8="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
    $a9="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
    $a10="{MD5}3paPsOthPZm+Aa59PX07AQ=="
    $a11="{MD5}3paPsOthPZm+Aa59PX07AQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule ldap_sha1_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}2z1AWxBnWZjAMCIxd9QucbTnoxI="
    $a3="{SHA}2z1AWxBnWZjAMCIxd9QucbTnoxI="
    $a4="{SHA}w8nOGdxcD9hTwwvIJSYR05gf+cY="
    $a5="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a6="{SHA}jfKuBmghi3SCLabn3k0YtngjC9Y="
    $a7="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a8="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
    $a9="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
    $a10="{SHA}041vADufHOgZCjqzpPsjStgREH8="
    $a11="{SHA}041vADufHOgZCjqzpPsjStgREH8="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule md5_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="21232f297a57a5a743894a0e4a801fc3"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="ed2b5c0139cec8ad2873829dc1117d50"
    $a3="ed2b5c0139cec8ad2873829dc1117d50"
    $a4="cf971ee17d571fc1ffa436a68762c381"
    $a5="63a9f0ea7bb98050796b649e85481845"
    $a6="0ec3772a8336ecddd6b6c61f01c05244"
    $a7="63a9f0ea7bb98050796b649e85481845"
    $a8="ee11cbb19052e40b07aac0ca060c23ee"
    $a9="ee11cbb19052e40b07aac0ca060c23ee"
    $a10="de968fb0eb613d99be01ae7d3d7d3b01"
    $a11="de968fb0eb613d99be01ae7d3d7d3b01"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha1_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="db3d405b10675998c030223177d42e71b4e7a312"
    $a3="db3d405b10675998c030223177d42e71b4e7a312"
    $a4="c3c9ce19dc5c0fd853c30bc8252611d3981ff9c6"
    $a5="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a6="8df2ae0668218b74822da6e7de4d18b678230bd6"
    $a7="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a8="12dea96fec20593566ab75692c9949596833adc9"
    $a9="12dea96fec20593566ab75692c9949596833adc9"
    $a10="d38d6f003b9f1ce8190a3ab3a4fb234ad811107f"
    $a11="d38d6f003b9f1ce8190a3ab3a4fb234ad811107f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha384_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="b25ed653dd08fcc715078f0e20046873afa39641eb13a5d2b5386e7567aa0ce84e41a936d80dadf1ce4fec4ab0111658"
    $a3="b25ed653dd08fcc715078f0e20046873afa39641eb13a5d2b5386e7567aa0ce84e41a936d80dadf1ce4fec4ab0111658"
    $a4="f24c53ddd7cde394c18be94fe068a5e173f2eb9b3dd5ac27843f45b3ff99ec046016f62962440c18b459039e21a2cbed"
    $a5="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a6="5d41c1d5bfdf6009ca9a08f07596bddc6614f9a1117374063e2f30a3d32b3c3b143713d6babe852884639a5c406d722c"
    $a7="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a8="46cb0934bc1afda5a06031f9849b0281bb5cd03767e318e0a877c5a51962dbaa7d7f0dc146ce1bd85176d856907aa2c9"
    $a9="46cb0934bc1afda5a06031f9849b0281bb5cd03767e318e0a877c5a51962dbaa7d7f0dc146ce1bd85176d856907aa2c9"
    $a10="7948831df64f1d058e894fab3f4e2c16fcd1b8881ef36935d7ae8a36c6f190a397e560bdaa52054ef8fa2606360de8e5"
    $a11="7948831df64f1d058e894fab3f4e2c16fcd1b8881ef36935d7ae8a36c6f190a397e560bdaa52054ef8fa2606360de8e5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha224_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="38f8d57baab9a443fc59d111e3469db3177218e0ce7af1792109afdf"
    $a3="38f8d57baab9a443fc59d111e3469db3177218e0ce7af1792109afdf"
    $a4="4918203cd3497ed94eb51a7ad11b69c25cd192fd2442d9648cf0af33"
    $a5="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a6="0a6dfeb55d4efd16bbf4256c7514cc2c5e26ec3b83d425d74777ffc8"
    $a7="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a8="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a9="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a10="7b1d927b3f3fdf4b21df08279c2a2f3bb868acfa80d50f3cdef23243"
    $a11="7b1d927b3f3fdf4b21df08279c2a2f3bb868acfa80d50f3cdef23243"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha512_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="b7da843eec64c93cb7bbee2e84e7f530bb7c9b637f0286fe5a6edc72a61a6e2193c45884fd6b8e13cb319f29d602315c4bcf70c3f74ac22224f3aace6e1f20ae"
    $a3="b7da843eec64c93cb7bbee2e84e7f530bb7c9b637f0286fe5a6edc72a61a6e2193c45884fd6b8e13cb319f29d602315c4bcf70c3f74ac22224f3aace6e1f20ae"
    $a4="8b580aa9570c124939c6aab9643dbce5dfaddec21728a2a39cc29c4220c052804f8196d7e653d1eb9183624ed002798c29cd36a96e04281dd90ddf13d0f1c670"
    $a5="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a6="12388bf1485b9e6b8337c8b7be09d14aaa57b146bd7ff4dbfaed71896f9bf9c69205a391d7559a1fa2e7d765d51170d2643b1ad1e4ca94187ff0dfaaf5eb62be"
    $a7="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a8="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
    $a9="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
    $a10="2598231ed04d6570f183dd24a9d01e7a0bd3fc709841451ee3475308f3256663fb1cebb744b52ff8392375cb45074fd394a9604e20ab33c6e94a4e75f1fe22a6"
    $a11="2598231ed04d6570f183dd24a9d01e7a0bd3fc709841451ee3475308f3256663fb1cebb744b52ff8392375cb45074fd394a9604e20ab33c6e94a4e75f1fe22a6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha256_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="b8d31e852725afb1e26d53bab6095b2bff1749c9275be13ed1c05a56ed31ec09"
    $a3="b8d31e852725afb1e26d53bab6095b2bff1749c9275be13ed1c05a56ed31ec09"
    $a4="b5d95422596277f0c2f91145fecbb57e11a0510fdf6f394e9757515588f680a5"
    $a5="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a6="9bb04416ad5bd45570cb76e9e909be4bc6c9e8766924154c60f552e60f34021c"
    $a7="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a8="04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb"
    $a9="04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb"
    $a10="02cb4b955bb1ddfacebd8fe7d7575c28a9d55e2d67817d13888ad827561c03ea"
    $a11="02cb4b955bb1ddfacebd8fe7d7575c28a9d55e2d67817d13888ad827561c03ea"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule blake2b_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="c1655ec09cff4f475a7c2036b481ae6148c0f919bb6fb6315050b9465689b794df017aa051ca3a11d01607a002f5a13d5690628203aa7f811d4c12cd96b36395"
    $a3="c1655ec09cff4f475a7c2036b481ae6148c0f919bb6fb6315050b9465689b794df017aa051ca3a11d01607a002f5a13d5690628203aa7f811d4c12cd96b36395"
    $a4="9e2758c60e5e575293047370f8490e7ab0982b021e7be709446fc39ff03ec69d678866c841a01e15c6c84c6ed696356b4c9790e9fe3793493cf56ecefd23cfe8"
    $a5="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a6="383594ced4c721f45475b82346d125496f3bc10705fc8f96dd9d80ac1956c5a0ce1649c5ed5ec3d70aceaff09f9f2c5b407dfd5ff3096a3595ac9bf2828c9a26"
    $a7="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a8="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
    $a9="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
    $a10="edd5a702c6032fec4099f6ad8e30de3e17579f7757cc5818001e1cff4a93a355bf225cf477f396239d3fdabb98cf4862a471fa25d555553092f5257c71d857d7"
    $a11="edd5a702c6032fec4099f6ad8e30de3e17579f7757cc5818001e1cff4a93a355bf225cf477f396239d3fdabb98cf4862a471fa25d555553092f5257c71d857d7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule blake2s_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="d710474a6f59faf00193fc458555910a67003851705cf90706e264948b6eebe4"
    $a3="d710474a6f59faf00193fc458555910a67003851705cf90706e264948b6eebe4"
    $a4="144e1234a1f0b962e603ee941b5832eccb48e65986d4ce5a53f1144e09228056"
    $a5="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a6="5bebb8f5c7d38c044b5e47ea0a80b77c71a75b7479848505c8853651bb37b2f2"
    $a7="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a8="218d2ba09e825de93bfa9f18f753f55accda639fee17705d3ec19948b8f7a1d0"
    $a9="218d2ba09e825de93bfa9f18f753f55accda639fee17705d3ec19948b8f7a1d0"
    $a10="e63bd481f42ba836b62fdd801abbb08da875eb684f0c7dca0c1adf3de5776d08"
    $a11="e63bd481f42ba836b62fdd801abbb08da875eb684f0c7dca0c1adf3de5776d08"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_224_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="36a88513cc12f0fb5041f9417b49822d1f05690c1b80f275a6c287ca"
    $a3="36a88513cc12f0fb5041f9417b49822d1f05690c1b80f275a6c287ca"
    $a4="792b61c9b94c490a85867d4dd85d451083b24411c070f09bcdf0f7d4"
    $a5="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a6="9ce1d539b79cd6f641893c7c7c20a116de3b9026652a017f0520802f"
    $a7="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a8="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a9="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a10="d218f30523776ebb67cf92ab59e208cc4b920880ad19245c5343bd23"
    $a11="d218f30523776ebb67cf92ab59e208cc4b920880ad19245c5343bd23"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_256_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="5a9cb4b1795fdc8982e907994a2e80eca49b6daf329c826d86903016391506ce"
    $a3="5a9cb4b1795fdc8982e907994a2e80eca49b6daf329c826d86903016391506ce"
    $a4="d614fea114454c8b39c7753dd94649c648c6fc0ae67db22adaed1069a50b0f9f"
    $a5="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a6="6c22ab290fa2cfb02c5b3b87f60cc8f3ab5bc1cfe37f4aea904d89b847f90342"
    $a7="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a8="8ac76453d769d4fd14b3f41ad4933f9bd64321972cd002de9b847e117435b08b"
    $a9="8ac76453d769d4fd14b3f41ad4933f9bd64321972cd002de9b847e117435b08b"
    $a10="9dd244510bfb39ac4a8be358c60e50ea60481934dc77badae9a6f5fb4bba56fe"
    $a11="9dd244510bfb39ac4a8be358c60e50ea60481934dc77badae9a6f5fb4bba56fe"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_384_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="d70b43000387175a14486f5c933e4f8012eb5bb0b00bf08fff9fb45165d4a315f9428b6d55062a91acc0e826bffbfc21"
    $a3="d70b43000387175a14486f5c933e4f8012eb5bb0b00bf08fff9fb45165d4a315f9428b6d55062a91acc0e826bffbfc21"
    $a4="95b2039bc45247a8d9617da94012665ceec1de90ad5b510a2018029549b36a953ece3c93de238b50b784c02214f69d8d"
    $a5="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a6="d3f94093942fa4baac771b17420a427d7cb6ace21505571b94ea14a4da4f7f66f7045a6622cf10fdeb754b8f132170f2"
    $a7="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a8="713d80421f781abcf2768f42fd1f17541c1fa03f68255d3d1fa4810590fdd77bb2a37d092f4b28fdfed380ba2dfafc7a"
    $a9="713d80421f781abcf2768f42fd1f17541c1fa03f68255d3d1fa4810590fdd77bb2a37d092f4b28fdfed380ba2dfafc7a"
    $a10="4c6c82392b1cac509ea7f0ca3bab653ec705278ef6b93843e4ca124ee859d335ba2ae7971a3f2d409bb9fda6110e3960"
    $a11="4c6c82392b1cac509ea7f0ca3bab653ec705278ef6b93843e4ca124ee859d335ba2ae7971a3f2d409bb9fda6110e3960"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule sha3_512_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="d572ef7d586b9b321c279832fc888ed002b9c857f139b7d933cd4d71f0d50fb37bd9e7b340b7d14558215f1798ed4c0e03a4946f73d0b10f523158b6514f0349"
    $a3="d572ef7d586b9b321c279832fc888ed002b9c857f139b7d933cd4d71f0d50fb37bd9e7b340b7d14558215f1798ed4c0e03a4946f73d0b10f523158b6514f0349"
    $a4="c0cb1bfa7c121f61719b34afd546a586faa76fc45abef34bdc8ee2b219638fe2184cd120136e4bfc918f900a64408d482c7eb30a8c7cced0cf988e75066a9d83"
    $a5="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a6="024a4739ae3b627ef99c691e7ac72712c900aee2e1940794858380fe03c3328b21f20f2a97418a97a3261ce03c32e3a4e0d59e0a94098d620cc24ab50d88719a"
    $a7="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a8="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
    $a9="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
    $a10="982d80e8264f2a7d61bc38d99aa24de22c4121d527d42ecef1ec418725c6cdf3fe8b07d4a2106147cf167a41551fb04dc81da279c9f779aac428ff15a4ecc73c"
    $a11="982d80e8264f2a7d61bc38d99aa24de22c4121d527d42ecef1ec418725c6cdf3fe8b07d4a2106147cf167a41551fb04dc81da279c9f779aac428ff15a4ecc73c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

rule base64_hashed_default_creds_zte_ssh
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte_ssh."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="YWRtaW4="
    $a2="b24="
    $a3="b24="
    $a4="cm9vdA=="
    $a5="VyFuMCZvTzcu"
    $a6="cm9vdA=="
    $a7="WnRlNTIx"
    $a8="dXNlcg=="
    $a9="dXNlcg=="
    $a10="WlhEU0w="
    $a11="WlhEU0w="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11)
}

