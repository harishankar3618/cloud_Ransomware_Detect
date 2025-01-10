/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_wyse
{
    meta:
        id = "6o5m6J34DSmuTogkFkoFmi"
        fingerprint = "b85b2925e53302dcb2b2881cdb381b46aa9056daad481bccaf9b65c10c97dce9"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="030b0c393eb8a601c800cea0054fe334"
    $a1="329153f560eb329c0e1deea55e88a1e9"
    $a2="d718adbe2a6fc8242442da6dfcf4f7a0"
    $a3="710c980e55faa60837d875fba41ed45e"
    $a4="d9d247a789f19a41659c6611240e10e0"
    $a5="e7d21aa3a0517f3395583852f8b6556e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule mysql323_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="14d9d83627fcfc9f"
    $a1="67457e226a1a15bd"
    $a2="74ab8ba42bdff4d8"
    $a3="7e2536a525d52164"
    $a4="38d09abd3efe27ad"
    $a5="52dbd9061c1ca2d7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule mysql41_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*564CD623B2DE65EE668E6AA20C7E92AB904A55DA"
    $a1="*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"
    $a2="*E7E9C7889AC83D022AD5E75BD4EB273581BE15F2"
    $a3="*0FE12DD55BF55F6C706D5B534BA05A8E88D41429"
    $a4="*6C6FDC5F8A65C193DCAC5E9C55383E33A0166776"
    $a5="*F3BCFC877EBD13E3D29A07D4F13DC8B3BFB461D5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule ldap_md5_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}4nwkeZPtqWajBHK5Vq7/vw=="
    $a1="{MD5}Y6nw6nu5gFB5a2SehUgYRQ=="
    $a2="{MD5}eNHkcN0qQ9n/TuzZO/m6jQ=="
    $a3="{MD5}xqM5EcxT35vbhKrI2GoFZQ=="
    $a4="{MD5}KCBaGi2Tkn+1g306SIKe9w=="
    $a5="{MD5}m5OhlqyB1VgseCL7+FsbJQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule ldap_sha1_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}2Oz1DQizD2jsyvw1Mrucn8xb3XU="
    $a1="{SHA}3Hbp8MAAbo+RngxRXGbbujmC94U="
    $a2="{SHA}lgdjmu9+bL0qJ1fZ7+MwYijOgcE="
    $a3="{SHA}indhO0deRgZDIf19oY0SbuNeUGY="
    $a4="{SHA}lXt3tlplJsgwsXeZz4fmOe9sIw8="
    $a5="{SHA}1vdy+Id4siYm0rhioUpGFIGFd44="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule md5_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e27c247993eda966a30472b956aeffbf"
    $a1="63a9f0ea7bb98050796b649e85481845"
    $a2="78d1e470dd2a43d9ff4eecd93bf9ba8d"
    $a3="c6a33911cc53df9bdb84aac8d86a0565"
    $a4="28205a1a2d93927fb5837d3a48829ef7"
    $a5="9b93a196ac81d5582c7822fbf85b1b25"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d8ecf50d08b30f68eccafc3532bb9c9fcc5bdd75"
    $a1="dc76e9f0c0006e8f919e0c515c66dbba3982f785"
    $a2="9607639aef7e6cbd2a2757d9efe3306228ce81c1"
    $a3="8a77613b475e46064321fd7da18d126ee35e5066"
    $a4="957b77b65a6526c830b17799cf87e639ef6c230f"
    $a5="d6f772f88778b22626d2b862a14a46148185778e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7714158131b38105ba1a1dd1e427a56d57119056fc672b1d28e79e452ad4456a037b69f8fc8ea09b8f84b0361c403ac1"
    $a1="7ed8c2c790aa83d6c3e404b5368f6832c18d46a0e98b9c7a7a5e3ef823e2c9f0e310abbf6f7ea9d9d883ccb64ec2736a"
    $a2="54dc0bc33ce667b5fa8052d34f340e4e843909703025cdfa71b69be58dd495d519314e825bce845c521219b37a396249"
    $a3="18cbfb902f16c781142cbe9c134e2b1ea7eded6c1a881678b6f1c5254b719540665f8ec465fd2f1995bafe794ba7d801"
    $a4="1b52b016bf98b7e67fe0cd4cebfb2d087036ac185c0611af3fcedc59ab80d3f7fc4aba658f900b7ddba64e81e40fa7bb"
    $a5="8c438a0b26136df1d7894c56ba13524949c91aa81a5ace7416743392b5ff09ce0f736ff2bb9489f6dbc4d7d834038edd"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="379a46e85d7be930571ab4ef689f10b258ea99318a014e62274479d9"
    $a1="871ce144069ea0816545f52f09cd135d1182262c3b235808fa5a3281"
    $a2="d35e70814fe2e2013fca23dd9b7cb67985f65f4aadd7c7d5d0f4caf9"
    $a3="a16b0181d196e34fc0b662184adcba6e440801e1c3cb7a47cabc162c"
    $a4="026538e5757f5fff4745bd506644010d39776027c1d3b302d4959dd3"
    $a5="101111087b7707e181db649390773370f8b4742746f0e88793b8c27e"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d716064bc0e1935ee1b8e66c9991d163307ae05c6a2c8518e750ee3d0c7e23f297ffa7e92f84a9fe718cf4215089c180920868569c11701da34803103737a0ea"
    $a1="99adc231b045331e514a516b4b7680f588e3823213abe901738bc3ad67b2f6fcb3c64efb93d18002588d3ccc1a49efbae1ce20cb43df36b38651f11fa75678e8"
    $a2="dd13455b8c4fe096351cb50144ecaa8cd132a70f120e5800b2bfa4796a73215e7ecbaea693a993300d3d7b0d885a25329eb4da9c4bf525e1dec415dada427fb0"
    $a3="47dac71b14bc4892f418563c2c44efd0d20df0588e2b6b65ed611dcda0f99e64b1373b57528ce2ef9a8d9f63d58e88c5ded5ad88032afec577789ce01dc6c43e"
    $a4="d633fb1d21b919712985b307728e1cae1220c75db85bcf8c11e50ddcd946b87618232618e01d22f258ea0b1febc06d75d9a76760736ad63494f18f6a0cb68882"
    $a5="dff2bc14e152889058764e1d58a0d7cd41509feb70d986f9757eff8947a0321a7710d97019a79241f0e5caf9f718e12d4950b3beb852f0ab78954a0cc9915d93"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="04e43902471c9ab7935a25360a0c2dc5915d0bcb601f5bcaf1a9fcc97f3bacbc"
    $a1="4813494d137e1631bba301d5acab6e7bb7aa74ce1185d456565ef51d737677b2"
    $a2="7ea9dc2a17d2b8888d6989855d3d13a391ef17cef3551f67dd01724189064d50"
    $a3="e41a2b6503b00fb488a6cc399cb6815efc768916b9acf7819a2375cc56540a50"
    $a4="a8d304e8471af555b0079bacfb70810e4783b5454a6f836ba3c2f23452f3308f"
    $a5="862f957bff971a511b2a804c86639d819d6c5a78cc82800440a14316ce692fd0"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a00776d99560ad680b1d3a12a848b54d0238559ae1264af9a8aceba445af6a3593c457f684ab23f9ef18a09bfd6f33b894f51775e169a6832e816b121e5cb34f"
    $a1="da23f3a4e096b0816ec2070050eac6cd9243240dad0b5cde6573e41d6852939ac5468aa9d81b5fbe156feb231a069f5afe8a5146630abc7807b1e0dcdaeb049a"
    $a2="11ece2058bc1d9b592b585b11d018f73067086e1e8b4d53c4cb6871bb9ba5c5673bca32a323b8d09819a1b9c35014610a0c71ac25f2e4f72c5e0db9fe2973fae"
    $a3="d5c6d67da69608b42fdac3fb407f209c71efa344d77e446f12e8b73bae873e8837e8eb03b30b29f4ac27a99ec080be30cf8e5da6423942a22f51dea3f0f196b4"
    $a4="fa3a147cd2a2861057edc69183e7171e0dfbbd76ecda9875c201c546c378e9ecf75d0cb13b22536540061ce0093cc5dbb08720e3f64ecc5991bdd2a624afa072"
    $a5="fe03ff34c8b135660afc2d240ba444ee1305182be6e0da51ff1343408b646da7401ea8c6ea4b87ffd04ae03c687eed6f6d078b35c9272c77a50c383ac8a8931f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="85f788510c30939dd22bb14176b615d585b0d500e3e2bc6b2b4a581d0a821420"
    $a1="0cb8a879dc5d94ed67eb49cc7a4d3052d6a346f2e28fcd9e10e5822aba92eb39"
    $a2="e74964bf0966ab850c05e184d2b4b2c6c23f75ea831b24a2956ef66c4b64e660"
    $a3="15435fbf1b82e0ad687264f141a79e10ecc498c6b2e30d1f489e0561ba15b879"
    $a4="34c9eda7c76c43f0dbe80aa71a87c709173327ab81f6a6159d4eabee624854f7"
    $a5="708109fb58c3df709b898c9b6dbe620816bc4f91f1c089b7e0acabd2acbcc4d7"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="def96bd6cde0d3bfe76786dfd9a2568d168335ef8223c8c74833c98e"
    $a1="3e42295e89a3a84ce7ee38e2ba317aeb57ca3164459bdf48f4da0e92"
    $a2="3d0f2bee930d492e3c2ee402175031cd4539f554522c424dc86d31f9"
    $a3="09620fd7325bcd5af39bdbfbd56a57991823aa514e84f19eb5c23c12"
    $a4="aa1f92728d09b520296e2969685797efa62ce7a9e03283b641c78ffd"
    $a5="e588e772284639c0b704b3a3579c75048f588e26d7391642e58db5a4"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="e787eeef9f29be13838111ba1c1267d6ed9f64d2ee862b863d16c32adff482bf"
    $a1="a00e4d3b352e9d11979549b9eef5dc951592f594488451e6cd86fdc4bce76a53"
    $a2="ff69d6c044543a4c14088b32b7acf489501324dcd38342347f855cff8fd6e9d5"
    $a3="f88ca7c8ebc412c940cc28cdb8ff244ef3b94421ef955241d1f6f54fa6557814"
    $a4="7b01874fbdacafa045b51b9cd998c4840c3c7746b9f5343723dcfde1a0ad979c"
    $a5="f325e8a45689e7c93a6a5540c3ab2ce6feaf763a3166b7dd3fd25cf7c6c6c92c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c3166cfbcdbcef03cbce88986f46fa957a133073ef15d5d73c2857eea941a3fe7321515e03e1293e1fa8f514d54ff4cb"
    $a1="aac595410801e93eadb099ac575ccc12e43be2c15e31e7991e908329e5beb0729881b3be9ccdb0eeb6eb79335ea38b6d"
    $a2="0242332157f9fa630c5fd3936cc897a0d6be23b7708738605be81a4895eac87a5fed7dfbaff90db486bcb229cde645e4"
    $a3="39bc1f48c0ab323564360bf47522ae8bf6482281525d5ef5e45081cb9c69cc506698a7a795032d7aa17e7554b62080db"
    $a4="55c64fec0ec5ebfa89674e5b259187849d53f1103effd7abeff4d8e34c0444164333aa9c011f0163e25bf3c07799e213"
    $a5="05278801e977cd312fc2530cb4a77a89a1b5f21568cb762f6706f80fc9cbbb5ec7c37375a4cd667695ae38e8988cfed6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="600700053a68627643a47c88b59df33ad817ef4c2173af8d46893e5a91adb50775925f1bcbd7579942cbb04713a7157c8ecde6132db5e07f77a4b4fff733ae62"
    $a1="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a2="9c15048bc812d9f22ecbad8eaf0677b43cb75d1865b50737e84879ec1adc1c819e728b92d11b2321243c1aa6ccb143ec241e476e4e2376cc888bbfe963e928a7"
    $a3="de919babf8aaa4b61eee7bb4d13c2b317977cc7552a2520041661b9babcd6dc542b8145a7b8efa5532c751887b99016fa3ab29acff4b7d99a3ba99d96eb22804"
    $a4="c5385c68a309241ad34389489227e61cb2ad7191aa392e08d9582c540514263f268491def99f1f479c12b79c2b97d13bcfbcbd59f2937636177849b5d0314f36"
    $a5="91d9afe9c786478c48ae16d1e70d70498defc79d2a28979635d077095c4e2658d765d9b459eaaddfcb81d9c7eaca42314b9c04b34bb0118e50233a901d7504a8"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_wyse
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for wyse."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cm9vdA=="
    $a1="d3lzZQ=="
    $a2="Vk5D"
    $a3="d2ludGVybQ=="
    $a4="cmFwcG9ydA=="
    $a5="ckBwOHAwcis="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

