/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_duhua_telnet
{
    meta:
        id = "7kDS4CGRJCmSlqwlGySpGp"
        fingerprint = "d998399de437a5ab25ceebe205e8c958580a61fffa0f9672332c42db23d64f7b"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for duhua_telnet."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7bdf5168c785cf4a77d28d25e2e18a48"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="7bdf5168c785cf4a77d28d25e2e18a48"
    $a3="329153f560eb329c0e1deea55e88a1e9"
    $a4="976e4dde60abb60ef9c05e3c3f441b78"
    $a5="329153f560eb329c0e1deea55e88a1e9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule mysql323_hashed_default_creds_duhua_telnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for duhua_telnet."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="560ce5200ef0376a"
    $a1="43e9a4ab75570f5b"
    $a2="560ce5200ef0376a"
    $a3="67457e226a1a15bd"
    $a4="01a5cc9371fe42fa"
    $a5="67457e226a1a15bd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule mysql41_hashed_default_creds_duhua_telnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for duhua_telnet."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*BD847EACD88B72A033D285956C00522996572898"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*BD847EACD88B72A033D285956C00522996572898"
    $a3="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a4="*031F474DF9A478DF74CD802B88F7D3106EC1A5A7"
    $a5="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule ldap_md5_hashed_default_creds_duhua_telnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for duhua_telnet."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}QgPo4ZISTII4bJVC2kuLTQ=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}QgPo4ZISTII4bJVC2kuLTQ=="
    $a3="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a4="{MD5}/7lUT4Qu9yTk3PDH7FNJyQ=="
    $a5="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule ldap_sha1_hashed_default_creds_duhua_telnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for duhua_telnet."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}ZAFWHYMmVA+NG+IRIIFDLY3fYto="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}ZAFWHYMmVA+NG+IRIIFDLY3fYto="
    $a3="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a4="{SHA}hOKNYeAXvX83Y34fJYGxvLM4XPM="
    $a5="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule md5_hashed_default_creds_duhua_telnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for duhua_telnet."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4203e8e192124c82386c9542da4b8b4d"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="4203e8e192124c82386c9542da4b8b4d"
    $a3="63a9f0ea7bb98050796b649e85481845"
    $a4="ffb9544f842ef724e4dcf0c7ec5349c9"
    $a5="63a9f0ea7bb98050796b649e85481845"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_duhua_telnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for duhua_telnet."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6401561d8326540f8d1be2112081432d8ddf62da"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="6401561d8326540f8d1be2112081432d8ddf62da"
    $a3="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a4="84e28d61e017bd7f37637e1f2581b1bcb3385cf3"
    $a5="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_duhua_telnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for duhua_telnet."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="5e5b054a1371434a3150ff26014bab146b50c563d6ea364b82d72d796197a475c3728cee12a5360def4a10766241f37b"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="5e5b054a1371434a3150ff26014bab146b50c563d6ea364b82d72d796197a475c3728cee12a5360def4a10766241f37b"
    $a3="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a4="0036f58edd0d3d6aa2261540fcf0142c79ed86afffbbc5cb0ee798464e6bd1fa62478ef5e3e3ec969b88951c06abdaad"
    $a5="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_duhua_telnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for duhua_telnet."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9fab6d8895b0e510404321f0a49de91b57954e9eff4fa6a657b4ce39"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="9fab6d8895b0e510404321f0a49de91b57954e9eff4fa6a657b4ce39"
    $a3="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a4="24cd058c3a3fa34905126bbbbafcaf2462cccdfc2473b249dbc7d6b3"
    $a5="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_duhua_telnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for duhua_telnet."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1d8ae800c77cc8dfbc496582223362557b3215f7e18a22b3b8fb7787b2c02407055d21f6e897d263aa05608259646e064f92606973bce4968e93efb43397c64b"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="1d8ae800c77cc8dfbc496582223362557b3215f7e18a22b3b8fb7787b2c02407055d21f6e897d263aa05608259646e064f92606973bce4968e93efb43397c64b"
    $a3="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a4="f10a7bd7251171649fc7cb40f6f64ac6d567020f601ca19337e83f56df69a502bde4664e4dac3674b07b45f273c24c67c2ac7bad42be3e39bfefa282e26c3cb5"
    $a5="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_duhua_telnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for duhua_telnet."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8f4ecd2e6bbc91770c629b6ad9b5769b744f140b3519b0d37039c369b23eeb9b"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="8f4ecd2e6bbc91770c629b6ad9b5769b744f140b3519b0d37039c369b23eeb9b"
    $a3="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a4="0843e4886ac1d3f1fd23c7c3c88f326d5d959f9043e2714c01386d3b475fa330"
    $a5="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_duhua_telnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for duhua_telnet."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c8eb5292fab086aa38702ea82a65e78d4ef68b8a5208f053ed64a84c188fec1d3aa9ca3638d83a8a3cd504a39db80691a44741c70ff72a8ae3ebdddff3f7c93b"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="c8eb5292fab086aa38702ea82a65e78d4ef68b8a5208f053ed64a84c188fec1d3aa9ca3638d83a8a3cd504a39db80691a44741c70ff72a8ae3ebdddff3f7c93b"
    $a3="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a4="24a495dbd2edaad8c2812b1a5642227033b765ae9a63e7418b771f7abde2511df6d269b4c242a23f8b74835176aa07a2b8b225e2604206796e8cf237387a8930"
    $a5="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_duhua_telnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for duhua_telnet."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e92ff577401fc80870583c9f437c1b6c3c5ecbb35388f3324469171c4549aeb1"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="e92ff577401fc80870583c9f437c1b6c3c5ecbb35388f3324469171c4549aeb1"
    $a3="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a4="7a5d2127b001ccf89cb47424c16fbed71e1f0f7b72e59f1edcd6bbb809b4d745"
    $a5="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_duhua_telnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for duhua_telnet."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="74cdde8b29020988c7bb0a05d8ff09c8e35f0e4264b526708800ca07"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="74cdde8b29020988c7bb0a05d8ff09c8e35f0e4264b526708800ca07"
    $a3="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a4="49bc88c0cd112900a7927ea54728c44bf297fd754cae5123ea2f61f4"
    $a5="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_duhua_telnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for duhua_telnet."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="68d1618215a76880a25b217f7d2db83f1af5f57aef6ae5ffe004d25f36d7828f"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="68d1618215a76880a25b217f7d2db83f1af5f57aef6ae5ffe004d25f36d7828f"
    $a3="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a4="7410d876c1018bc227b0e6d5a4416db0ada4da67212802d2f47e6010538ef437"
    $a5="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_duhua_telnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for duhua_telnet."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4ae6f91928b2a42add6d7628ef395d1b9d66900e8379aca8d778048462cde81cbe53ef595ae7ec64d49b2f0adea1a1fa"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="4ae6f91928b2a42add6d7628ef395d1b9d66900e8379aca8d778048462cde81cbe53ef595ae7ec64d49b2f0adea1a1fa"
    $a3="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a4="c71eb2db07f5a558f539650fa77d5f0f66e460cc227adc0736d86afc8d9b88b8bb4d56089e001826b015f1a72721108f"
    $a5="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_duhua_telnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for duhua_telnet."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d8cb68884b73300f1d449f3a207d9bcb734683bceca68e22897a1fe793344162fbb0359d89da2b12ece7664715f092e7c24274c8a69ce9cb5ff0b865aa425338"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="d8cb68884b73300f1d449f3a207d9bcb734683bceca68e22897a1fe793344162fbb0359d89da2b12ece7664715f092e7c24274c8a69ce9cb5ff0b865aa425338"
    $a3="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a4="9c4bcb9a262fa9f4de782a2cf33db2000a160beec315b43d63e00d330e1f784bcca99f645eb685761b17f1456604f832bc8bf52efbb587cc6c6bdc8efc534dba"
    $a5="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_duhua_telnet
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for duhua_telnet."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="N3VqTWtvMGFkbWlu"
    $a2="cm9vdA=="
    $a3="N3VqTWtvMGFkbWlu"
    $a4="cm9vdA=="
    $a5="dml6eHY="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

