/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_silicon_graphics
{
    meta:
        id = "18dkPAxIIeAKUdBLNIb5XV"
        fingerprint = "d455a138fe2cad1f91e4e095555312dfcea7b992bae3ab46a9bc164e1d890162"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="77e918b2be14ef27f80fc5151ca73e54"
    $a1="77e918b2be14ef27f80fc5151ca73e54"
    $a2="c3a23eb3f9e371403d51ab7a5810d2c1"
    $a3="c3a23eb3f9e371403d51ab7a5810d2c1"
    $a4="2ccf1f9609a7c6739112e14f760d565a"
    $a5="2ccf1f9609a7c6739112e14f760d565a"
    $a6="e5b4cf7b85c2e8f8027b5395ef7de843"
    $a7="e5b4cf7b85c2e8f8027b5395ef7de843"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule mysql323_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6fb19ab3555227d9"
    $a1="6fb19ab3555227d9"
    $a2="6d6608be5e6f7fa3"
    $a3="6d6608be5e6f7fa3"
    $a4="3c91bc542731520d"
    $a5="3c91bc542731520d"
    $a6="2a4dc9205bcc0ce6"
    $a7="2a4dc9205bcc0ce6"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule mysql41_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*733C60540129614C6C5E22B112BB4EB5E71DED40"
    $a1="*733C60540129614C6C5E22B112BB4EB5E71DED40"
    $a2="*2CEF1DC762FF13BDAB527E25C9B7F51921DB0B18"
    $a3="*2CEF1DC762FF13BDAB527E25C9B7F51921DB0B18"
    $a4="*F46C97C5A17F055A0EB082C6D44EDE61D9599DDA"
    $a5="*F46C97C5A17F055A0EB082C6D44EDE61D9599DDA"
    $a6="*66EC1375EADD4D06F1B64E96E8BAA2E7DAF3F26E"
    $a7="*66EC1375EADD4D06F1B64E96E8BAA2E7DAF3F26E"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule ldap_md5_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}aTG3NdaPyOmqsLFUfcD+JA=="
    $a1="{MD5}aTG3NdaPyOmqsLFUfcD+JA=="
    $a2="{MD5}BuPTb6MM6glVRROYVK0fuQ=="
    $a3="{MD5}BuPTb6MM6glVRROYVK0fuQ=="
    $a4="{MD5}8KQCWztJs+JWAEUD7jHfjA=="
    $a5="{MD5}8KQCWztJs+JWAEUD7jHfjA=="
    $a6="{MD5}H29CM04XCaTg+ZIq14mRKw=="
    $a7="{MD5}H29CM04XCaTg+ZIq14mRKw=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule ldap_sha1_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}hgXE8qiVZU85JBbjQ9xgDXo4OW8="
    $a1="{SHA}hgXE8qiVZU85JBbjQ9xgDXo4OW8="
    $a2="{SHA}LaC2jfiEF1K7dHp2eAZ5vNh8YhU="
    $a3="{SHA}LaC2jfiEF1K7dHp2eAZ5vNh8YhU="
    $a4="{SHA}LIu9Tro7dNkK19nNi2XyVLwNe1Q="
    $a5="{SHA}LIu9Tro7dNkK19nNi2XyVLwNe1Q="
    $a6="{SHA}qb16W1g8vgguLIUFlccaaBhibxA="
    $a7="{SHA}qb16W1g8vgguLIUFlccaaBhibxA="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule md5_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="6931b735d68fc8e9aab0b1547dc0fe24"
    $a1="6931b735d68fc8e9aab0b1547dc0fe24"
    $a2="06e3d36fa30cea095545139854ad1fb9"
    $a3="06e3d36fa30cea095545139854ad1fb9"
    $a4="f0a4025b3b49b3e256004503ee31df8c"
    $a5="f0a4025b3b49b3e256004503ee31df8c"
    $a6="1f6f42334e1709a4e0f9922ad789912b"
    $a7="1f6f42334e1709a4e0f9922ad789912b"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha1_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8605c4f2a895654f392416e343dc600d7a38396f"
    $a1="8605c4f2a895654f392416e343dc600d7a38396f"
    $a2="2da0b68df8841752bb747a76780679bcd87c6215"
    $a3="2da0b68df8841752bb747a76780679bcd87c6215"
    $a4="2c8bbd4eba3b74d90ad7d9cd8b65f254bc0d7b54"
    $a5="2c8bbd4eba3b74d90ad7d9cd8b65f254bc0d7b54"
    $a6="a9bd7a5b583cbe082e2c850595c71a6818626f10"
    $a7="a9bd7a5b583cbe082e2c850595c71a6818626f10"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha384_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="05e15148eb181e5ba1bb2fa208756dbfa6a60efd7af22581a4f9e8f39a4d6270636e0b66d2313656f12c7aee33e1e4d8"
    $a1="05e15148eb181e5ba1bb2fa208756dbfa6a60efd7af22581a4f9e8f39a4d6270636e0b66d2313656f12c7aee33e1e4d8"
    $a2="1820ddb65200b50165054c985b456a7038a834016b2a83d695bd6fa67902f24adc343c200e39c05330cb79e9d454aafe"
    $a3="1820ddb65200b50165054c985b456a7038a834016b2a83d695bd6fa67902f24adc343c200e39c05330cb79e9d454aafe"
    $a4="299988a11250fdce76bb4d820c9e749d64b4c44b5543c98cb915a33f37b1a7b0bc4100ef3089a70dd59616731fc0cdbf"
    $a5="299988a11250fdce76bb4d820c9e749d64b4c44b5543c98cb915a33f37b1a7b0bc4100ef3089a70dd59616731fc0cdbf"
    $a6="8cf71de2400e59624ac7e3da1f0e11ef08fe43611a9b795fef417fa9d1eca47cdb776c6a1b6a31aec34dd2799a4dc737"
    $a7="8cf71de2400e59624ac7e3da1f0e11ef08fe43611a9b795fef417fa9d1eca47cdb776c6a1b6a31aec34dd2799a4dc737"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha224_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="963015e1b149431497ff6ff5ddbb667ae11b92c674f17ab2a6d85908"
    $a1="963015e1b149431497ff6ff5ddbb667ae11b92c674f17ab2a6d85908"
    $a2="e3255393979d9f406ef58249d67bfcd058f74c0316ef18e551660e4e"
    $a3="e3255393979d9f406ef58249d67bfcd058f74c0316ef18e551660e4e"
    $a4="b9473e318638c4f74946c3f9938538d4b5963fa4d3923ce7c74208ca"
    $a5="b9473e318638c4f74946c3f9938538d4b5963fa4d3923ce7c74208ca"
    $a6="ca6b9d99f81b696103a5ccc88541f43a2076f0e5592a062ebd21a333"
    $a7="ca6b9d99f81b696103a5ccc88541f43a2076f0e5592a062ebd21a333"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha512_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8acda221280c5684a907eee7a8b96f88025b2815c03ee2ffefbc51f221d6197d44f01621c9420d45e93c876aea090813dd3f5182d202c1cef036e3a5651a393a"
    $a1="8acda221280c5684a907eee7a8b96f88025b2815c03ee2ffefbc51f221d6197d44f01621c9420d45e93c876aea090813dd3f5182d202c1cef036e3a5651a393a"
    $a2="37f5080f1558fd09bc2382154690f45bf3e38a6923bf3d7517bbd6d1bbb69277d716541f97ead094e9609f9ef5723c1b9289095728f7de28a091c0ab96e26a7b"
    $a3="37f5080f1558fd09bc2382154690f45bf3e38a6923bf3d7517bbd6d1bbb69277d716541f97ead094e9609f9ef5723c1b9289095728f7de28a091c0ab96e26a7b"
    $a4="5f9311fa05854c9357d2fa4ab0b0db37b50481e0e7e907cb048da771b534037cf279e22161091c4b7131d1210ed402c8a744595f7d614683db0994f27000d15b"
    $a5="5f9311fa05854c9357d2fa4ab0b0db37b50481e0e7e907cb048da771b534037cf279e22161091c4b7131d1210ed402c8a744595f7d614683db0994f27000d15b"
    $a6="efd22db8c6e2bbacf88bdcf49b91831d2398e63bfebf519824e68682ba9f9549506fbc34b49008a50a8d9ed59cec5fb0b3caea7590d3ef9feebc77b542dadcbb"
    $a7="efd22db8c6e2bbacf88bdcf49b91831d2398e63bfebf519824e68682ba9f9549506fbc34b49008a50a8d9ed59cec5fb0b3caea7590d3ef9feebc77b542dadcbb"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha256_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="0a7373be0796ab9e1f7c2fdec700220092dd851a692c9fe99680c3636be09454"
    $a1="0a7373be0796ab9e1f7c2fdec700220092dd851a692c9fe99680c3636be09454"
    $a2="c0d2856b74d0df05b9d4456b177950351bd88e98b77f12574dfb7a911acee0d0"
    $a3="c0d2856b74d0df05b9d4456b177950351bd88e98b77f12574dfb7a911acee0d0"
    $a4="d7b44809a0359169b755a7030186df928be6b79eff65dc6534e17aacbca31c49"
    $a5="d7b44809a0359169b755a7030186df928be6b79eff65dc6534e17aacbca31c49"
    $a6="038740ef981ab56f4e0529bec9101d1a1d1181886b0c8a917c98029636341360"
    $a7="038740ef981ab56f4e0529bec9101d1a1d1181886b0c8a917c98029636341360"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2b_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9bb44cf4c431cfc1a6dbdab87cca99d5ab05b52290f2c8ad8038a083f4a16dff02a5a10b5bcaceae303db40d3bd12977d72865e6172c4850536a11233fccaa93"
    $a1="9bb44cf4c431cfc1a6dbdab87cca99d5ab05b52290f2c8ad8038a083f4a16dff02a5a10b5bcaceae303db40d3bd12977d72865e6172c4850536a11233fccaa93"
    $a2="f391fe682d35c14ba9af25a963b4a01b5f1b967154e01d01d43a23263720820b0a9293a8af09caf2d9afd2b4fa70a997c9323d0381979c0da3e4447bf6bcb89a"
    $a3="f391fe682d35c14ba9af25a963b4a01b5f1b967154e01d01d43a23263720820b0a9293a8af09caf2d9afd2b4fa70a997c9323d0381979c0da3e4447bf6bcb89a"
    $a4="d6fd18c9016526b943d45581ab14652513a935263fdd148a4de8361f08f890ff6f13f65d2983875a0f76c352bfa9c09128d2632e5b137f184d50e9ab948f7e22"
    $a5="d6fd18c9016526b943d45581ab14652513a935263fdd148a4de8361f08f890ff6f13f65d2983875a0f76c352bfa9c09128d2632e5b137f184d50e9ab948f7e22"
    $a6="cfb4b045634bdeaa2fccc366e9e7fac7ceb2bcfc2a19e6c8ffd6c3f49736d91c2acc6e0911365ae6bf30c3a4aeb2f47dd1ba9356ae2887b9bbf2ddee9640711c"
    $a7="cfb4b045634bdeaa2fccc366e9e7fac7ceb2bcfc2a19e6c8ffd6c3f49736d91c2acc6e0911365ae6bf30c3a4aeb2f47dd1ba9356ae2887b9bbf2ddee9640711c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule blake2s_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a8b6d185970be2a73a51fdbcd1784cca22c4572ec4545e3a1e7586bb8002ae86"
    $a1="a8b6d185970be2a73a51fdbcd1784cca22c4572ec4545e3a1e7586bb8002ae86"
    $a2="663df51d8382d92d97be9678b5304abf1a7fba9aa7d0347d87cf7e68f8ada4a6"
    $a3="663df51d8382d92d97be9678b5304abf1a7fba9aa7d0347d87cf7e68f8ada4a6"
    $a4="abaa5bb05208fd64301e73fc3242743bb6f93bdb9250f8a50068c994eb740636"
    $a5="abaa5bb05208fd64301e73fc3242743bb6f93bdb9250f8a50068c994eb740636"
    $a6="1e362c2d9282db64245523a78a1396686c03ac820508cbef1989eef0155cbecc"
    $a7="1e362c2d9282db64245523a78a1396686c03ac820508cbef1989eef0155cbecc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_224_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="62c4b1af4ba2f221d933569821a0997059e19bbde671349c5d51768d"
    $a1="62c4b1af4ba2f221d933569821a0997059e19bbde671349c5d51768d"
    $a2="3cd2ee56b00c1db314a8ee2c447a40661e1f93f9d5ae09678f0cd690"
    $a3="3cd2ee56b00c1db314a8ee2c447a40661e1f93f9d5ae09678f0cd690"
    $a4="7661f49c9614243acbe577af50efc47e3c47b5dddf37637cbbed148d"
    $a5="7661f49c9614243acbe577af50efc47e3c47b5dddf37637cbbed148d"
    $a6="73f59cabe9d81169ca10f33c23312876b4ebc6463bf321e3c266f9c9"
    $a7="73f59cabe9d81169ca10f33c23312876b4ebc6463bf321e3c266f9c9"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_256_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a26e38bcc8a9c93e27ca32364c0422a18703c967dfb8242016cb49788534d3cb"
    $a1="a26e38bcc8a9c93e27ca32364c0422a18703c967dfb8242016cb49788534d3cb"
    $a2="2127c901c00c98ea3722ff5fc9726e75ce636cee16bd90ef26b71853c199705c"
    $a3="2127c901c00c98ea3722ff5fc9726e75ce636cee16bd90ef26b71853c199705c"
    $a4="5797a2d496895ea43837aea62626527461192f68d69c93c42afcfa8584942bd3"
    $a5="5797a2d496895ea43837aea62626527461192f68d69c93c42afcfa8584942bd3"
    $a6="598053f426c422688da27cccafb9ac6590fa32be0be93f696437b5fe308269e3"
    $a7="598053f426c422688da27cccafb9ac6590fa32be0be93f696437b5fe308269e3"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_384_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9005fb09af985c0c5ba9ea4e6ff3517cc9b2a3f92135f97fde61d08a4631199b500c8b505510c8928c6ce85f88e85b34"
    $a1="9005fb09af985c0c5ba9ea4e6ff3517cc9b2a3f92135f97fde61d08a4631199b500c8b505510c8928c6ce85f88e85b34"
    $a2="1a82cfc35f4183db590dee37b965a7ea50db27ec00b9ea58b450110a3e78781c24f15f595940ff8906b232b3633be711"
    $a3="1a82cfc35f4183db590dee37b965a7ea50db27ec00b9ea58b450110a3e78781c24f15f595940ff8906b232b3633be711"
    $a4="8489527df88be00ac879ec53e7e57dfd9d4ee27b0e3a5d8e7a90ec476055efd599ba2a7184ee9d650870e9f5c593a778"
    $a5="8489527df88be00ac879ec53e7e57dfd9d4ee27b0e3a5d8e7a90ec476055efd599ba2a7184ee9d650870e9f5c593a778"
    $a6="0a7e2eda3e1c44ad8f61de02625b5920b8d616aed321611084b9c260ac63255b9b44f30092aaf1fdf9b39ea3f617ff99"
    $a7="0a7e2eda3e1c44ad8f61de02625b5920b8d616aed321611084b9c260ac63255b9b44f30092aaf1fdf9b39ea3f617ff99"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule sha3_512_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="89e533dd6df467690c56e30f45045faa70758578b624fbd42b6835a2d8e5b3f15db3e79e59f11a78437189c6d3f3ece9222a36e7d11aa76b2f303c3fead8e252"
    $a1="89e533dd6df467690c56e30f45045faa70758578b624fbd42b6835a2d8e5b3f15db3e79e59f11a78437189c6d3f3ece9222a36e7d11aa76b2f303c3fead8e252"
    $a2="6c6e86f951088a5af4eb989fed4cef51a9558b14cc768b694c0d67bf0f36c3ea88996b50701daf0a1b0478cb6dbc505e4813fce0f0f496b2ec7008e2d3621eeb"
    $a3="6c6e86f951088a5af4eb989fed4cef51a9558b14cc768b694c0d67bf0f36c3ea88996b50701daf0a1b0478cb6dbc505e4813fce0f0f496b2ec7008e2d3621eeb"
    $a4="bb0ccdb55d5e6b7c526a06513c253cf85365e18365423fcb273a8d7eb41ea1cd28f18ba3de00935d36bce42f9db19e8b6d139361f05ba130adf367d0469d7a48"
    $a5="bb0ccdb55d5e6b7c526a06513c253cf85365e18365423fcb273a8d7eb41ea1cd28f18ba3de00935d36bce42f9db19e8b6d139361f05ba130adf367d0469d7a48"
    $a6="e3591dfce542f25cc5cad019bd0f92c78a7543ba734716ad61462d48a57b0ee2eda58edccb7049de181af02ee563cf38f6b796aaf0bdcccb80d379075d577489"
    $a7="e3591dfce542f25cc5cad019bd0f92c78a7543ba734716ad61462d48a57b0ee2eda58edccb7049de181af02ee563cf38f6b796aaf0bdcccb80d379075d577489"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

rule base64_hashed_default_creds_silicon_graphics
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for silicon_graphics."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="NERnaWZ0cw=="
    $a1="NERnaWZ0cw=="
    $a2="ZmllbGQ="
    $a3="ZmllbGQ="
    $a4="dG91cg=="
    $a5="dG91cg=="
    $a6="dHV0b3I="
    $a7="dHV0b3I="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7)
}

