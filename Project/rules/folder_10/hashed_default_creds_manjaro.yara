/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_manjaro
{
    meta:
        id = "7TxLZBSpE8HQh01hdxBOyp"
        fingerprint = "05e0c6c67a8c2c1417a71694c6215421bf2995132433b0ba23b44bfcc3e5acf0"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a611d159a226d1f27e7fe70daed1bb8b"
    $a1="ce543295d829fd9de48f47008f93ff05"
    $a2="657ebb6de35bea4d20a6b0fa0851b8da"
    $a3="ce543295d829fd9de48f47008f93ff05"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql323_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7fa311df4ed1c857"
    $a1="1546546e38673b56"
    $a2="72979a5b6ede5e32"
    $a3="1546546e38673b56"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule mysql41_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*4B251511F5DE09F5603EDADE2E468A76C2E240A6"
    $a1="*49AA0B0308454DCE01A23BB7E3EFBE5C77F11B66"
    $a2="*46ADBBFA69A68FFDF36246D68FBC78E3EEA83CB1"
    $a3="*49AA0B0308454DCE01A23BB7E3EFBE5C77F11B66"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_md5_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}yMgeNZq6gkLi9luHLixn9Q=="
    $a1="{MD5}j7tl1TQKPambSdpKWE9CvQ=="
    $a2="{MD5}ipi+GVyGwoV8xBha9T48hg=="
    $a3="{MD5}j7tl1TQKPambSdpKWE9CvQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule ldap_sha1_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}HhzUUYpiYFe3j+B3UgoUyiLnOls="
    $a1="{SHA}/fu3HvphFfVB5GnPqbd/vUZLB7M="
    $a2="{SHA}oDov96UnKd659M0+LFBhGNC1Ux0="
    $a3="{SHA}/fu3HvphFfVB5GnPqbd/vUZLB7M="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule md5_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c8c81e359aba8242e2f65b872e2c67f5"
    $a1="8fbb65d5340a3da99b49da4a584f42bd"
    $a2="8a98be195c86c2857cc4185af53e3c86"
    $a3="8fbb65d5340a3da99b49da4a584f42bd"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha1_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1e1cd4518a626057b78fe077520a14ca22e73a5b"
    $a1="fdfbb71efa6115f541e469cfa9b77fbd464b07b3"
    $a2="a03a2ff7a52729deb9f4cd3e2c506118d0b5531d"
    $a3="fdfbb71efa6115f541e469cfa9b77fbd464b07b3"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha384_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="fa3bae37672148acf5397a4f4badeb3177f54115d2db704b0853f9301510807e76a59f62213bcebb2d7e8ac89609e36b"
    $a1="8d1bf654dce97cbc88b017bebae635d094425323bfb418fd1182882f40741e8ac5b104f85d8af1fe26ae76eb4b991f7e"
    $a2="4aac17c66b16861a8c8d205adf61f2870bc67dd81459810f927fdc013813bc9467a9b43c535ab20ca357c9487ad1b23b"
    $a3="8d1bf654dce97cbc88b017bebae635d094425323bfb418fd1182882f40741e8ac5b104f85d8af1fe26ae76eb4b991f7e"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha224_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="750c9dedf0e64aa63a3e1332d76af11503417b8a0ecb137012856f37"
    $a1="76e197434d1b65e3440915ef1930aad0702e34dd355e419af3aea28f"
    $a2="60fff09a536ae771070ff0e7cbe146e7857b6f0ebd21f57811a47b4e"
    $a3="76e197434d1b65e3440915ef1930aad0702e34dd355e419af3aea28f"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha512_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6eb96a4ad1a6a0f4a9c692b2f0d9beaf6ca09d3a954ec2c191473a6c91db43a2038bc7dc145ef6fde73f4c1d2f6c778d467f142b03f80972981107316cd89202"
    $a1="a5f5fe6fcc9860296c14a22f0a4cb48348c3953edbe94ed4941d10e6615ffee9736c8ad3a6c64b32b9c794edec9effc275f45be607852a28fd88dd8e67db12ec"
    $a2="fca6e7467e75955a8d89235a5aea84c78c247bf60104160a53fa840e9d53bb9ad88a41d1b16e3bbc06d593b70c4e3ea255d160f79cbe7f95bb80ac507ee931ad"
    $a3="a5f5fe6fcc9860296c14a22f0a4cb48348c3953edbe94ed4941d10e6615ffee9736c8ad3a6c64b32b9c794edec9effc275f45be607852a28fd88dd8e67db12ec"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha256_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="80c7d61e5b4fa27be3b32b00705b5386648eb09faa5876f958c18fa11beec342"
    $a1="4df87556ebc9fe46c1eef23662f6787f855c788d09f61dec25eb9f422fa0d3f7"
    $a2="d0711a9964cbbeb11d992fb183ba18dd9db3b71b8604f67cdfcb127af02b3af4"
    $a3="4df87556ebc9fe46c1eef23662f6787f855c788d09f61dec25eb9f422fa0d3f7"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2b_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bc8c46e2fe0f14db91eb6215e9de1143d4cb8d4ab67b5f877e3528998caaa55ea3b746523408942c9b3b9cc6b9520d76025f061a5d6dbf82f94456d84a245172"
    $a1="18063aed84a0d6785ebbc098f5a9f8a24297be6502acdd901df5ba96705d07532856c22fa870a88ac30f8d6f885241ca3790b6e87d4c3b639d082ff598da3093"
    $a2="40a5c6a46c0d33f0303777b2ab597e61136c1303b6b71830b76bc11442d9e30f647ebfa1128e3ddeab10d60db997f1a266caa3d9dc63ab159bee60adce8d6269"
    $a3="18063aed84a0d6785ebbc098f5a9f8a24297be6502acdd901df5ba96705d07532856c22fa870a88ac30f8d6f885241ca3790b6e87d4c3b639d082ff598da3093"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule blake2s_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0ca90c49077c4a25741a4fe8feca7e2afa9d0359282a49a9e83e76f0e4ef4aa0"
    $a1="7ce7bb762c0da6a2decf180c6952bd46c655f209f1f7575a947a68275f751e67"
    $a2="fd04dfd3e89eb170fce660fb16d618cb932cb15103ecc2186d7058edf8e5f5cd"
    $a3="7ce7bb762c0da6a2decf180c6952bd46c655f209f1f7575a947a68275f751e67"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_224_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="aa1a3e928132dbcde7415d71081e408e6ab793b2978aa52f578e7ae0"
    $a1="20eb8970892df6a888f6dfdcd32ff9d194a155fa66cee9f9c4eda8fe"
    $a2="d268ffa2d566bfdb8323d78507a07ffd01e01596ee5295c134e803a3"
    $a3="20eb8970892df6a888f6dfdcd32ff9d194a155fa66cee9f9c4eda8fe"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_256_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6fd3561002c724955ac67802df8148a46da29c772aa8795babed0e38896820b1"
    $a1="7defdb045e7e527c20174f1ad436860d9f8ee58f22178401553c6b5ef38e5218"
    $a2="6fda8afd648bb8717964ade45d3165b7b54061c7369d8807edecd9dbd0a19d13"
    $a3="7defdb045e7e527c20174f1ad436860d9f8ee58f22178401553c6b5ef38e5218"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_384_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0065adbe09bce08fc62d02ff50cb3f1789975949533671a6bfec493bb07d63ab5afdb45f74080fca093fe2dc845fd8a6"
    $a1="59d290af8d204c7538ab53f39b3e2d0516e78ba2613633082fcae36ba581c60f4580e4ec9ccd6692ea6bf81949194c79"
    $a2="f19041445e380ac3a00d6f94c00dce1a2868d7433a24878664084a1a8898ce4a155343a55a3c0452c9ff9df256644534"
    $a3="59d290af8d204c7538ab53f39b3e2d0516e78ba2613633082fcae36ba581c60f4580e4ec9ccd6692ea6bf81949194c79"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule sha3_512_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="c056828e33dfe0798d4380e3dd37f2086bde9947d5320708c8afbde286aeaf8c0ab78521d2fde6472cdac57a5f066a01adc7cfb7d768fb187ec4e68a7137bda5"
    $a1="3a6a797f2e60f766597dca5af1ffdb10232c5f639059676a9153f856b17dd8c0c4b3e5a5f4ef9fb1ff3a64c1ec2d4b6a83054d8f935e919fc29e6377a99f0bb4"
    $a2="f15999c451b7d531d05c7e10dcf63219867d98820e724c5ba2f8c5518bad2088fef915cf911f025d854fcc9335fba674fe422aa7ceadc2f1a3e05d35b6bb8aad"
    $a3="3a6a797f2e60f766597dca5af1ffdb10232c5f639059676a9153f856b17dd8c0c4b3e5a5f4ef9fb1ff3a64c1ec2d4b6a83054d8f935e919fc29e6377a99f0bb4"
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

rule base64_hashed_default_creds_manjaro
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for manjaro."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="bWFuamFybw=="
    $a1="dXNlciBhY2Nlc3M="
    $a2="bWFuamFybw=="
    $a3="c3VkbyBhY2Nlc3M="
condition:
    ($a0 and $a1) or ($a2 and $a3)
}

