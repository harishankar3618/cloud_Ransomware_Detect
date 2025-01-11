/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_innovaphone
{
    meta:
        id = "1tXn6bRMyQCZuLRSFmqrCs"
        fingerprint = "a3682d942e5e8c871d24c9bd159b7f98ad8532b4875bd07b0399aa6989a9eea9"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for innovaphone."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="b5713166c244e9b76453e33d7b0108a8"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="d253da24a4a08d782353b67fdf43b50a"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="5a2fd9f024799c287f6c1a7308a9b4a4"
    $a5="209c6174da490caeb422f3fa5a7ae634"
    $a6="af7bb4de6e9865c99768742dbec245e0"
    $a7="209c6174da490caeb422f3fa5a7ae634"
    $a8="baf7063de5f3a6fefa025ee13ef22f1c"
    $a9="209c6174da490caeb422f3fa5a7ae634"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule mysql323_hashed_default_creds_innovaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for innovaphone."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="76f5418b5892e8f9"
    $a1="43e9a4ab75570f5b"
    $a2="76f542465892e5b4"
    $a3="43e9a4ab75570f5b"
    $a4="7883fe324b24e75b"
    $a5="43e9a4ab75570f5b"
    $a6="79e6a91a48b3fe2c"
    $a7="43e9a4ab75570f5b"
    $a8="018d3ccd6002f30a"
    $a9="43e9a4ab75570f5b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule mysql41_hashed_default_creds_innovaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for innovaphone."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*332AFFA277E69DFD6ACF8C290D2F2443BB4DF247"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*1126687001B192EAA9862829B7DF450268BC2C4E"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*A2CDDCE7F93E015F831D62ECDD3D729AC4DF80ED"
    $a5="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a6="*B095D61636ABDEB80AD869A39CF80B1D62869E16"
    $a7="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a8="*36EB1EB015C8857C3008760DF7C6BE1368CA80B7"
    $a9="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule ldap_md5_hashed_default_creds_innovaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for innovaphone."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}HkhEF6+RSkX0erjpySnymg=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}CTf146zHnqC3REd/h75+qw=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}xjyOge4EvGjiK4ldBKw5Eg=="
    $a5="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a6="{MD5}gCOjTljDr8Zrp9Tf4zsZMQ=="
    $a7="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a8="{MD5}EJa2E6mPxCgrHZf/CS94Bw=="
    $a9="{MD5}ISMvKXpXpadDiUoOSoAfww=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule ldap_sha1_hashed_default_creds_innovaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for innovaphone."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}cQ87PIlJyiXZq3bO7o5Up0j6YLc="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}hx/cXhZui9PhALtRCABQacIO4dQ="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}94rTwrlyjEAG3DdpHvnHv5IWIDQ="
    $a5="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a6="{SHA}Exlp34vG78y5vISmSNICVWxFHus="
    $a7="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a8="{SHA}/n8aHXTY2tAJXE6SGirywoDrwKo="
    $a9="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule md5_hashed_default_creds_innovaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for innovaphone."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1e484417af914a45f47ab8e9c929f29a"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="0937f5e3acc79ea0b744477f87be7eab"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="c63c8e81ee04bc68e22b895d04ac3912"
    $a5="21232f297a57a5a743894a0e4a801fc3"
    $a6="8023a34e58c3afc66ba7d4dfe33b1931"
    $a7="21232f297a57a5a743894a0e4a801fc3"
    $a8="1096b613a98fc4282b1d97ff092f7807"
    $a9="21232f297a57a5a743894a0e4a801fc3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha1_hashed_default_creds_innovaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for innovaphone."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="710f3b3c8949ca25d9ab76ceee8e54a748fa60b7"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="871fdc5e166e8bd3e100bb5108005069c20ee1d4"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="f78ad3c2b9728c4006dc37691ef9c7bf92162034"
    $a5="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a6="131969df8bc6efccb9bc84a648d202556c451eeb"
    $a7="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a8="fe7f1a1d74d8dad0095c4e921a2af2c280ebc0aa"
    $a9="d033e22ae348aeb5660fc2140aec35850c4da997"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha384_hashed_default_creds_innovaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for innovaphone."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="72c710ee853be580eace0404d15a8529b999ce768282d247edfb5f1761ad1acf55167f1f02cba51e0bf8851abc52b979"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="1f89da18f9aa02ae455c3faa05e234a1b4c9e513a0107a071c949b0f55f20fb58bed242e890318104a82159ceea557dd"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="086ee868babc960f520bedea014a51cf9b8207551ac6b07054eaf047b1f5e52fb88a269e992d755e4e427e0aba639a93"
    $a5="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a6="c05383a40b1a728e622cb1a6cca33609b90ba3aa55f7d349905a4bb7df710c4fee71654e4b8f4e3a0b7c1e0edc94ba61"
    $a7="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a8="e5b776b0cc12280635539479c3d9769e2d0e6adf7caf3a31f6a5cdc1523d0fec43589de8caf6b7033307608fc3503754"
    $a9="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha224_hashed_default_creds_innovaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for innovaphone."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6c1780d2e0641114de80cc45af08a42b5fd4adb620757cddea1425ed"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="54de9f549802408266b498aa0795d30c1897885fcc1bb09d145066bd"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="6129af98071d1faeedec060f32765984ede646c8ca7e6a6a3b5a590b"
    $a5="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a6="4de8527f71f83046204e069f5ddc99b4a8cbb134558e64e07f356aea"
    $a7="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a8="2c91654d497e0890333e21835c4df9f79d503488a572050a85da85c0"
    $a9="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha512_hashed_default_creds_innovaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for innovaphone."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d7558964b4d5d41193588b68027abba5dff4d0d676619fb60566776be2bb71e22dc4ca1b2bed4eede5b5675328fd16122a479013942a0eb714f081174cd094b4"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="887add6b2e801cd26a7141db688905064d37e71333485cfee7fcfc74fe3057c1509c325821cfc5abe6bf1d4f3bb2c95508639ceb172f2a343c3c7f6c93429873"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="598535b96b94c8bb8608a633367406bc5239955d83cc483b3fbd64c9e6f72f94d079c65f38689c3dd0fa87f7514e380d63958d21d610245dbf1a0dd668b585b2"
    $a5="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a6="6b9e99be87ea6b47b88b2f1db364d6d65767ab937d47a2d9bd5f199b84526f13dd8a4f683caa5f890faca0a68e70ae3acea5077970a5cf99465d0872bc8b6fc8"
    $a7="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a8="f5ae6bcd00181012da454092f4168a1f69626c41d7ca1ac6b8e4fc163329bfc1996c49fa0cfc47b124168dc98bf01d7c7eebbe4eead39727ee399a132e261ca9"
    $a9="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha256_hashed_default_creds_innovaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for innovaphone."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9499bf89be95ea909dfaf994dd3ca10aef1b0a777bf4487447fc63e3ee341e56"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="6be46db521e0dbab28af73d6f1c05b121349f86980bcfff6f8e5747a68b83726"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="9dc66612d0115e46f873eef5a08fdfeca721d2071cf99ac3f715043d4c1dae1f"
    $a5="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a6="3627efc27171cb33bdc754c3a30f53c8451409fe103f06798413f0e4efa7d740"
    $a7="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a8="b65b1683acce0c7606b54988d712d14452227319a74fe757e305491a0527d8a2"
    $a9="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule blake2b_hashed_default_creds_innovaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for innovaphone."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bed0149c2f4e1c5047fa6cf58d58943ca64c6816b9d6760671a793fab4c7c1e58771deca2688e00273104170f1db456ca905a7e384c044908b0ad271140d6c4b"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="b31187757dd7db9ab4b1003eba9a64a8a6d5ab3a9ec19a45ce4b7c1f92bb20b42dd564871011f4ee834662fcbecfd19b4855765f86f18c6d6822e4ca8e81eaad"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="4c2ddaf16e91e595865019cd3bf4953bdec3111eab55ca004476fc5355894c4301e06179990b1a35d421a5088557859c9ed288a8b3ee068df94505160688c60f"
    $a5="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a6="a1425f068d5b6eecd11a713656bed57ca5ff263b2bf5c9c113cc6c63d4c3f18abeb01c44bc65a958e621257d121ec583dd1c2040836674aef5caea7f9c540f91"
    $a7="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a8="91658ff49c3f8cebc6cf335280c767674f58f7236b01700f7efc2b8a6f90fef2ad128f1a0393545878d7e17b7ec225f35e873d0873446e9af0ea74f6493440a2"
    $a9="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule blake2s_hashed_default_creds_innovaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for innovaphone."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="47e657ed382b9ccd90e7ed99ef03875a8a889763eedff7619a2db2013b4d227e"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="0e0e2c14f32dd7082b63f56289672589318ca6e120b645af276feb5613d8086e"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="11e3a73c902107a57c58ccb28ba41c212ddcecf61accb6bbabfec4fcf2eb7256"
    $a5="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a6="0b94f3c7e12dae439f46ebce8f26fd12553779cafb5ff26eb49b2032c200ab03"
    $a7="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a8="122669e58e7c55ad70af067f3ec79b2a4b79c1b5b161222c0b0d591fa75fc581"
    $a9="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_224_hashed_default_creds_innovaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for innovaphone."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fb4e650fe26e9a480185b1f4cc6c90cd40d71a80e51005ad2e420a5e"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="1fa922a41e62f013788457d3dcdcb09c0e36ec599131ffd3ee5c1110"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="439e4eab1fb7f618269901a54ec4fe3635fe9d43f69ca18ccdeda784"
    $a5="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a6="7605ffcb272fa228b4909dc1d5cee7823224779dc9c1666ab82c576f"
    $a7="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a8="6ea3ae034180da4e585421158d55a50a4be0a4738393008baa0fb320"
    $a9="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_256_hashed_default_creds_innovaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for innovaphone."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="baeab9dd52f54ee487b1d5e0b42bd9e2522804cb55461775827c410013ae0162"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="46889eb6ed1e277ecef35d73ab49cdebd87430dd6780bf26c64ab59a7273e534"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="58982b2309cb57ad241c83b84b83f7002094f1085932139f908d2f74adf5f7de"
    $a5="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a6="e6bd129b0860334a00d8c652e41cbb052b790cd9036ae49f2701d20ac720f84a"
    $a7="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a8="05ad047267dcd7aafc48485e1623a6906fc8570abc9422968cdbf1dfd7b3206d"
    $a9="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_384_hashed_default_creds_innovaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for innovaphone."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="83f7ec87323d1a00326fe103355b91829166b5178f4f7ac418885ebdc9881b3dfe2f7b6728e5cb75a7b0369718c84f7d"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="ffaec14c60219c82b4b8ad584fcf7f8c640b64380dce51a1811f7c6c98a3c9f8d07e66b4dcf05f56eaa05de9e57a5eef"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="cdacb28f67e273a3324952715f195a99303d8d313c0859e6eaf578599d69059f6e5c0381e702a85841f438d6d696e777"
    $a5="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a6="39b4e90e161df46f104086a15c6f7ac48c0cd4685a4bd34d971ce04805007ee0d6536fae0b1799e1ac0a172f59d52518"
    $a7="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a8="7f3542e474fbf328862ddd1348b0eadbf197fca57b80993089a3f62ce07b76564e8cc37df66151f3e168b4970c351032"
    $a9="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule sha3_512_hashed_default_creds_innovaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for innovaphone."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c98fa2e674d0a618afe0edf9bfa088381afbfe02606e86c5fa8914f6e350edd429d2042039d52dd42ff84d1ce5a4e8fdea0d4b7f280471a4df974d59d86fe0a8"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="3b7c05400a18cdf135a1b0290f289fcbe91417feee27c19c1b55a3ad47feb3af57912ef0464348f284cf58df13a9f022f5ae443214195559001910fe91a402e2"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="0ed32913df4202a950324028dcda00567688bbc02bd6e2865cd415c9787d1e0cf64f5f7eb437fc330afd680e7a89f6afa07ffcfc1d45daa8a44177c2bdebd64e"
    $a5="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a6="17a5fb73c757dc1463d52e61d0bd51b4c49b4b557e1c6cd66f1ca2e49b9fd9fb5f93299e2f944af3c3183aa0a29e353c31efc049bae6c91e5be2845beec1fb63"
    $a7="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a8="ad77694977fadbae8890c9bc01653f4ea060598472734533136a6e5c3b2469fc6ccdc8eb6ca9ee3810f0a9c4b98349286bfe9d1e0f965fbcbdf1515233bcdb6b"
    $a9="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

rule base64_hashed_default_creds_innovaphone
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for innovaphone."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="aXAyMA=="
    $a2="YWRtaW4="
    $a3="aXAyMQ=="
    $a4="YWRtaW4="
    $a5="aXAzMDAw"
    $a6="YWRtaW4="
    $a7="aXAzMDVCZWhlZXI="
    $a8="YWRtaW4="
    $a9="aXA0MDA="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9)
}

