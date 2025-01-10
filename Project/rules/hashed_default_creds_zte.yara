/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_zte
{
    meta:
        id = "6i0AkU0xrmxF4FsmW9G1Ie"
        fingerprint = "447525771e2460d94663ce63ecf47262922793cf84347fd8f6b5d52d972178b4"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="178b064527342016b963177ee399f71c"
    $a1="209c6174da490caeb422f3fa5a7ae634"
    $a2="8cec5308d16b7b319c395f74988dde17"
    $a3="209c6174da490caeb422f3fa5a7ae634"
    $a4="57d583aa46d571502aad4bb7aea09c70"
    $a5="57d583aa46d571502aad4bb7aea09c70"
    $a6="011c7e804b2a3e5be12eaa63478e5ada"
    $a7="f9b38088c195c15e3cf9fbeecebf14f4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule mysql323_hashed_default_creds_zte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3c22309e255eca6a"
    $a1="43e9a4ab75570f5b"
    $a2="6384e9056103be5f"
    $a3="43e9a4ab75570f5b"
    $a4="1a486e7929011a28"
    $a5="1a486e7929011a28"
    $a6="0a5384c92a827813"
    $a7="0acaedaa7baad4c7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule mysql41_hashed_default_creds_zte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*112FB8BF2207F7DF5F9BE855EBD8E38180CE6F6D"
    $a1="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a2="*E7CDE8E34F73D02760C9A0C1CCCB119DC0AA187F"
    $a3="*4ACFE3202A5FF5CF467898FC58AAB1D615029441"
    $a4="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a5="*D5D9F81F5542DE067FFF5FF7A4CA4BDD322C578F"
    $a6="*6229E5FE22F86C1DE4C6847D8A76F1C31A7CFA15"
    $a7="*FA8ABDA23E9E13C815145E381C45FE1129B1B0B2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule ldap_md5_hashed_default_creds_zte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}O8a1Ul7Ne3rjaKSOpZ8NaA=="
    $a1="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a2="{MD5}VJE8sjco3C/Ppshv5WfxOA=="
    $a3="{MD5}ISMvKXpXpadDiUoOSoAfww=="
    $a4="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
    $a5="{MD5}7hHLsZBS5AsHqsDKBgwj7g=="
    $a6="{MD5}tRLHNjNm5a/REwKefL9ewg=="
    $a7="{MD5}7VDox+tysejNT4mvCFp8Kg=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule ldap_sha1_hashed_default_creds_zte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}kVbm+eYXzUqHFK9fj2sqUB+2sR8="
    $a1="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a2="{SHA}6FJWYewOh82gVpfm4fBQp+xrLoo="
    $a3="{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc="
    $a4="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
    $a5="{SHA}Et6pb+wgWTVmq3VpLJlJWWgzrck="
    $a6="{SHA}nojrAjmaiUfK0jlbAVldhIx6HIc="
    $a7="{SHA}hExZC6HvN1fYisSVG/Jp0XYVyHo="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule md5_hashed_default_creds_zte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3bc6b5525ecd7b7ae368a48ea59f0d68"
    $a1="21232f297a57a5a743894a0e4a801fc3"
    $a2="54913cb23728dc2fcfa6c86fe567f138"
    $a3="21232f297a57a5a743894a0e4a801fc3"
    $a4="ee11cbb19052e40b07aac0ca060c23ee"
    $a5="ee11cbb19052e40b07aac0ca060c23ee"
    $a6="b512c7363366e5afd113029e7cbf5ec2"
    $a7="ed50e8c7eb72b1e8cd4f89af085a7c2a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha1_hashed_default_creds_zte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9156e6f9e617cd4a8714af5f8f6b2a501fb6b11f"
    $a1="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a2="e8525661ec0e87cda05697e6e1f050a7ec6b2e8a"
    $a3="d033e22ae348aeb5660fc2140aec35850c4da997"
    $a4="12dea96fec20593566ab75692c9949596833adc9"
    $a5="12dea96fec20593566ab75692c9949596833adc9"
    $a6="9e88eb02399a8947cad2395b01595d848c7a1c87"
    $a7="844c590ba1ef3757d88ac4951bf269d17615c87a"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha384_hashed_default_creds_zte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bda90c54524168b4df84d1dd8008f3994987bd136fb8ab26a17c677a8255585678415d95e5e6c3608701d6cae67fe6ae"
    $a1="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a2="4f741e737e89ff8f6c806ddc61ad9b15ad67702e2329f6ed92d51c6b12223a81b31f97841c6ce6fb22d8c99d68c07815"
    $a3="9ca694a90285c034432c9550421b7b9dbd5c0f4b6673f05f6dbce58052ba20e4248041956ee8c9a2ec9f10290cdc0782"
    $a4="46cb0934bc1afda5a06031f9849b0281bb5cd03767e318e0a877c5a51962dbaa7d7f0dc146ce1bd85176d856907aa2c9"
    $a5="46cb0934bc1afda5a06031f9849b0281bb5cd03767e318e0a877c5a51962dbaa7d7f0dc146ce1bd85176d856907aa2c9"
    $a6="3aa4921f19834b4b445cad30e6a760ad7998f195e34b16690b74e7b31b8da1e543cd23ee01c33b2b8b907de63b086385"
    $a7="85e2993e1713ef21cb42470c22bebdda1cfdf29a48cd8ef1edc8b9651f7ef7b181c260db565f12e07a6200f8a5992025"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha224_hashed_default_creds_zte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0d8e47ec9eff6e80c36099e742808d802dd561a7561cd35218b874ec"
    $a1="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a2="144395f4c37bfe49b683aa17874aa9bd00e026ba174b92d514df3f07"
    $a3="58acb7acccce58ffa8b953b12b5a7702bd42dae441c1ad85057fa70b"
    $a4="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a5="147ad31215fd55112ce613a7883902bb306aa35bba879cd2dbe500b9"
    $a6="037921f105c0ad458943f805364d257f4daae2498a302d3437a96bd7"
    $a7="289c88d937d35f3669c94e2ad1fc9f56d0af0267683e85f00d281dec"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha512_hashed_default_creds_zte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4245998d35231f71d12f9dc299ffe2bc22ed3c1c3f59ff825bf6a27bc875169f0219c08c9e0560ae97e43a1baadeaaa9e82ba6adb451a6f1c62449c48a9024dc"
    $a1="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a2="50defc7946c9046a21b9d1087d4e8da7020df62b42efae6aeb7a20fd2593b190c6e3f26ba35dc0a9e9d7574bd95bc7364e42b2e4fa7d2d0dcd5f623e0e24beab"
    $a3="c7ad44cbad762a5da0a452f9e854fdc1e0e7a52a38015f23f3eab1d80b931dd472634dfac71cd34ebc35d16ab7fb8a90c81f975113d6c7538dc69dd8de9077ec"
    $a4="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
    $a5="b14361404c078ffd549c03db443c3fede2f3e534d73f78f77301ed97d4a436a9fd9db05ee8b325c0ad36438b43fec8510c204fc1c1edb21d0941c00e9e2c1ce2"
    $a6="4fb0b502ff286c02473bdf07f55ec08eccab7a232ca1033f8d9b6a00c125788b13e5dfd0c26ad49191759496e8f0734d78b6111cf1cce87eea0c9c9fc1870d6b"
    $a7="8c608bb59aa76e6ad37bc1c9edfc62edb0a57b5fffd98e1a5e7358c0b245a30c910bbfbd1918a124cac7878e71fe7d469810d85fe92f93977b8f49aa58ff9f5f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha256_hashed_default_creds_zte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a338f3fd70f2ef27d9abb9b5138ed364331391ead8fde16ce980a5ddd80641a2"
    $a1="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a2="db423d4559164b1fc407f603c139754495ac63175d55c0c242d61bc6f4257d00"
    $a3="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    $a4="04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb"
    $a5="04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb"
    $a6="7b4740a6da9c3f2d91862a0b9adefa9d9e137d3eca72015babb8a95be16b2506"
    $a7="68b265878c455777a7b72e200023ba1ae40e8f4711980301c24894dc57397fe5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2b_hashed_default_creds_zte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="23524a214912c6ed56056f056fd8fc39bd3335d7ddb19a6e3d6fc7687fb7d7e5ce2e9ddd4e6813c895ee0f64cb8b80176c6c48ab54e106ffd5aa548afccbbbbc"
    $a1="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a2="8ec48dee3fa5e834e5fa9df6a246e28e23b56ba54efbd01df3d72e89ee2e7bf9978afc3672be0861b1b6a6baea46cc079204f93dc2def62f9caa34224f8d806a"
    $a3="bfcce2c19c8563fd4aa66f6ec607341ff25e5f6fe7fa520d7d1242d871385f23a3e8e80093120b4877d79535e10b182ae2ec8937d1f72f091e7178c9e4ff0f11"
    $a4="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
    $a5="7c4c19165f106d9de2fcb67a6f4d907be2fa7776b1149ff82b69aa74348c0605ea4ef749ce4f5c2ace34cef80a0ce14a480284aa9b6463317b42a11efb64ec38"
    $a6="708bfd626e1068239a806708995e69de6dd7e9b8dd4498e3576badb863cbda0f4adf7d2b9228a187958e8c73cfd1f8515b713628b00e52e0d1adad35143a38da"
    $a7="5e42125e70ceb375f8af88ed9c0fd8af0ce4012df0ca3091251840e355dc39dc6bdc380937aafb0e546b9c9caf025568c8560922cf7568e9ed6188ec0aafe187"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2s_hashed_default_creds_zte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e1049b13039cfa4b843088d34893949c9909f49cd6eb25c2c5d5e8a6e9903264"
    $a1="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a2="a11bde1449d9643432c60e7ec2f529becb86b6d705443eeadb19103e66bf407e"
    $a3="327e7e3821f5f6d33c090137f979bf48ee62e9051c1610e1d6468ecb3c67a124"
    $a4="218d2ba09e825de93bfa9f18f753f55accda639fee17705d3ec19948b8f7a1d0"
    $a5="218d2ba09e825de93bfa9f18f753f55accda639fee17705d3ec19948b8f7a1d0"
    $a6="43ff7aae0202244490a24d2dc387a033e89de77acc8176cd21ee10640feb9197"
    $a7="a21604fd0fd9899fa037315816cf01641cbc09e6a7e14b00bbc76fc233953fb2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_224_hashed_default_creds_zte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="3870ae613631953c064dc90cdd84d9ba0394da10837533cfc57b0ce9"
    $a1="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a2="4e9b94a7b9bfd0587eb08ecce05e6891690fc74096bf12f5f252eb3d"
    $a3="a53fff8dd075bed169e164743231ff533d8b9260b0b8073f0a4c1d20"
    $a4="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a5="335d5c1d592d95574f90c486ec26b75dfa65c92e5058bbeb98e32a5b"
    $a6="9cd34d2002e0842320aafc357167e172a11f3151529f7a18a5c40e1d"
    $a7="6d44a7d2bb55aeb28c4dfbc50074355b037dc92819ca29a200d6602b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_256_hashed_default_creds_zte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7ae777faef553371b4832779c0d505039bd73aedad5205a156d9f73808b6d1cc"
    $a1="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a2="743ae16c60c96649c0bce9a9c019513252bdc9cff5a38996ae40d45e5988880d"
    $a3="fb001dfcffd1c899f3297871406242f097aecf1a5342ccf3ebcd116146188e4b"
    $a4="8ac76453d769d4fd14b3f41ad4933f9bd64321972cd002de9b847e117435b08b"
    $a5="8ac76453d769d4fd14b3f41ad4933f9bd64321972cd002de9b847e117435b08b"
    $a6="8770aac7db0cf2226ea290034955a49bb59c69e666d5d2f1b3c77ed50340aeb9"
    $a7="2e228e404125b81011357b353c738d18d018fe587fc6520c162f6bc654ae0663"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_384_hashed_default_creds_zte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f330280078eedee79f2d2cf5b6de1136984fc1ce5eba8452ecc283c1f84fbf60b968c2767a9407d5646f8c1e13890bfe"
    $a1="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a2="0dedff25a5e9d803773cb80953c7a962103da028a6c69b7a483426acb880d340a9b779eeb5ee3a738b0e83af859426f2"
    $a3="9765a57f2010506383de91052915ce8bafbdb39f3e5a8c1a1693a0076365d37abbfd3305881ea3b5fa1426316afd7df3"
    $a4="713d80421f781abcf2768f42fd1f17541c1fa03f68255d3d1fa4810590fdd77bb2a37d092f4b28fdfed380ba2dfafc7a"
    $a5="713d80421f781abcf2768f42fd1f17541c1fa03f68255d3d1fa4810590fdd77bb2a37d092f4b28fdfed380ba2dfafc7a"
    $a6="2a1caa6a50da964f85291200f3e4dd35f49a634dd18620d736457c69c297724187fbc448018cd480adc523f401322f65"
    $a7="3f96b2db838678ffa54c4e255c08b57b99e1ddae50ff8a0de2b2b44cf21f8c8d67e7ffddfddd9b09bda8df6c768c8ff4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_512_hashed_default_creds_zte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="94821b0ea102d097e2c7b4715ebaf2e7423eba8814a537dfcad5c9cfac09d0d8be5be1af0c317f44295ff92abb2a8f89e5c25c820a82a8dc19bfcc299ec6a24a"
    $a1="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a2="fa25fa9134708d672c9c55622800621c70f72878b3d1acf1ec2d8351c01792957b4db4ed2b7b00a3dc44510bc0135629eddfa130d97572ca0dd1951b35d76060"
    $a3="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a4="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
    $a5="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
    $a6="ede1629e063689808f7abb5355aff8599039f1e4854eaac0a351aa7f2bc70417c393af8bd2db0d77d827d421ca18f2c4b3800fc19ea8b4b94c35b294b864a168"
    $a7="7841bec97afc1fce68d833e1b37f7ac9a5acde407ce5ca14a4e481b61047aab194c7c2886599bb5c940158c8bdb8906557788dd0c172ee608049aa31543eedfc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule base64_hashed_default_creds_zte
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for zte."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="YWRtaW4="
    $a1="VGVsa29tZHNvMTIz"
    $a2="YWRtaW4="
    $a3="V2ViQDAwNjM="
    $a4="dXNlcg=="
    $a5="dXNlcg=="
    $a6="QURTTA=="
    $a7="ZXhwZXJ0MDM="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

