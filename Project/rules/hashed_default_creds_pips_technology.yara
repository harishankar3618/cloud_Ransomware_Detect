/*This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.*/

rule nthash_hashed_default_creds_pips_technology
{
    meta:
        id = "xiOToRyft7MZy7bm5LuQN"
        fingerprint = "61ee3c41d631dbd9f2d73601742eb55843130bb1991ff01fca4edab6a85d3993"
        version = "1.0"
        modified = "2024-02-15"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "NTHASH"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="7929aba6ecc04862b491bb16553bb43a"
    $a1="7929aba6ecc04862b491bb16553bb43a"
    $a2="99e03982a9c5864058e3c5ed439fd5dd"
    $a3="99e03982a9c5864058e3c5ed439fd5dd"
    $a4="1bfcc4fd0083b569ad0aad3692eb3f38"
    $a5="1bfcc4fd0083b569ad0aad3692eb3f38"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule mysql323_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "MYSQL323"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="4cf672dc63c42510"
    $a1="4cf672dc63c42510"
    $a2="639dacf14112dca6"
    $a3="639dacf14112dca6"
    $a4="4096c0030b1b8446"
    $a5="4096c0030b1b8446"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule mysql41_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "MYSQL41"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="*223789B76D5FF103AFF6BE5048960E2C896DD842"
    $a1="*223789B76D5FF103AFF6BE5048960E2C896DD842"
    $a2="*ECF6F9EC4B299A3717A0478BE89346CCAE3D266F"
    $a3="*ECF6F9EC4B299A3717A0478BE89346CCAE3D266F"
    $a4="*88DB7E9ED285F6940F943544B7EF5FB6F2A2C795"
    $a5="*88DB7E9ED285F6940F943544B7EF5FB6F2A2C795"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule ldap_md5_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "LDAP_MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{MD5}jqZfCJDflBuE40qoLlxrSw=="
    $a1="{MD5}jqZfCJDflBuE40qoLlxrSw=="
    $a2="{MD5}2P0yIdjAKCkXpb57L+JvDA=="
    $a3="{MD5}2P0yIdjAKCkXpb57L+JvDA=="
    $a4="{MD5}HGRJdpV7rXnL9QRbVegiMQ=="
    $a5="{MD5}HGRJdpV7rXnL9QRbVegiMQ=="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule ldap_sha1_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "LDAP_SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="{SHA}zqyQddKZzDdZ78YeGuMVwpQHb38="
    $a1="{SHA}zqyQddKZzDdZ78YeGuMVwpQHb38="
    $a2="{SHA}9MYgqVZWste4wP7XYD7WS8AsyVI="
    $a3="{SHA}9MYgqVZWste4wP7XYD7WS8AsyVI="
    $a4="{SHA}jU2N1z1fHUBNJd0w2yXZG4rs4nY="
    $a5="{SHA}jU2N1z1fHUBNJd0w2yXZG4rs4nY="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule md5_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "MD5"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8ea65f0890df941b84e34aa82e5c6b4b"
    $a1="8ea65f0890df941b84e34aa82e5c6b4b"
    $a2="d8fd3221d8c0282917a5be7b2fe26f0c"
    $a3="d8fd3221d8c0282917a5be7b2fe26f0c"
    $a4="1c644976957bad79cbf5045b55e82231"
    $a5="1c644976957bad79cbf5045b55e82231"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha1_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "SHA1"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="ceac9075d299cc3759efc61e1ae315c294076f7f"
    $a1="ceac9075d299cc3759efc61e1ae315c294076f7f"
    $a2="f4c620a95656b2d7b8c0fed7603ed64bc02cc952"
    $a3="f4c620a95656b2d7b8c0fed7603ed64bc02cc952"
    $a4="8d4d8dd73d5f1d404d25dd30db25d91b8aece276"
    $a5="8d4d8dd73d5f1d404d25dd30db25d91b8aece276"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha384_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "SHA384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="f7ef8a755d780d5045094eb18c000e55ede5cc3fe04aefc244e4afab1c65356e2eefb0038d1bb2a71be9363b6c5ecb38"
    $a1="f7ef8a755d780d5045094eb18c000e55ede5cc3fe04aefc244e4afab1c65356e2eefb0038d1bb2a71be9363b6c5ecb38"
    $a2="ca2391f24162e854b3998ec1933192a772e7d2314c782d7549061192c72c5391fdfec15f776bd43aef2243796cee4d40"
    $a3="ca2391f24162e854b3998ec1933192a772e7d2314c782d7549061192c72c5391fdfec15f776bd43aef2243796cee4d40"
    $a4="24132c317f30eb4826be0607b62288aed409f02faa89ac1d00c15b38af25fe62b33aea44e502f59a5ac52c04ae2b36e2"
    $a5="24132c317f30eb4826be0607b62288aed409f02faa89ac1d00c15b38af25fe62b33aea44e502f59a5ac52c04ae2b36e2"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha224_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "SHA224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8445e8f00c0b50e7f5c193fdbbdbd568251e9dfa557b86a0fa9d2e80"
    $a1="8445e8f00c0b50e7f5c193fdbbdbd568251e9dfa557b86a0fa9d2e80"
    $a2="8c4a8629b717f56ab7ef69e4109ffba5544a9b876cadea69b2b9906c"
    $a3="8c4a8629b717f56ab7ef69e4109ffba5544a9b876cadea69b2b9906c"
    $a4="33c6eac441c00060f6f82b7a6b5744728a91961ac546c14fe01f468c"
    $a5="33c6eac441c00060f6f82b7a6b5744728a91961ac546c14fe01f468c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha512_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "SHA512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="cdcbabc29330396d743b15e1ccabd4dc695400bcce835452038db36740aa6f6fb259ab36d7252b5bd210bfa671a8e541115bc7883db5b083e6b7030d98c0adff"
    $a1="cdcbabc29330396d743b15e1ccabd4dc695400bcce835452038db36740aa6f6fb259ab36d7252b5bd210bfa671a8e541115bc7883db5b083e6b7030d98c0adff"
    $a2="a9766f35b14a93656f1e828266e84eb9329ec81aa782fb63d64204744d8a9d4b13ef9928c47beb64404775b053a27a23ff3c1b1550f0281c78872efcf5a07e1b"
    $a3="a9766f35b14a93656f1e828266e84eb9329ec81aa782fb63d64204744d8a9d4b13ef9928c47beb64404775b053a27a23ff3c1b1550f0281c78872efcf5a07e1b"
    $a4="6523a4937120dd1d8cbe6779e1b24cc509dc2f7c8767015bdd494c9ec4ebf0ca801d24dbd83c8ddccf92c17b78c749b163d2332191bedd06a8ac2ebc3212557c"
    $a5="6523a4937120dd1d8cbe6779e1b24cc509dc2f7c8767015bdd494c9ec4ebf0ca801d24dbd83c8ddccf92c17b78c749b163d2332191bedd06a8ac2ebc3212557c"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha256_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "SHA256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="47d89b52f9cab096f8244daa587658709dc3b5bc138f838e1d5d3563cc798894"
    $a1="47d89b52f9cab096f8244daa587658709dc3b5bc138f838e1d5d3563cc798894"
    $a2="75af9aa69e409c7eda5e19b19f6b194bc3cd0cbfd932b37397652a1ca9c0f277"
    $a3="75af9aa69e409c7eda5e19b19f6b194bc3cd0cbfd932b37397652a1ca9c0f277"
    $a4="b6b422bbcf4833221ded639a0de48d239e6ee04ab5e3bf6f5de0e043341e3cc5"
    $a5="b6b422bbcf4833221ded639a0de48d239e6ee04ab5e3bf6f5de0e043341e3cc5"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2b_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2ab3ba43ea506c1a65908712926d8eb9e01e58007c08196c0fb062bd4e0c4039cec4b3a30562b8b98a96d9b489f50b4b8aa90ced4fe795eca87ca32f22ab7395"
    $a1="2ab3ba43ea506c1a65908712926d8eb9e01e58007c08196c0fb062bd4e0c4039cec4b3a30562b8b98a96d9b489f50b4b8aa90ced4fe795eca87ca32f22ab7395"
    $a2="f0952788879fd69863bedd8e86f137848c641aec6ea26bda632bf971a6e29ee7b8044b9f71d861b30d6f4dad95e3165cae9730bebdf3581b7edeab3fa660860c"
    $a3="f0952788879fd69863bedd8e86f137848c641aec6ea26bda632bf971a6e29ee7b8044b9f71d861b30d6f4dad95e3165cae9730bebdf3581b7edeab3fa660860c"
    $a4="576a277fb6154cbbd270f8de1a4c0bbda1a18732de7242c377216d459b15d26b440d97dc6ea16c26861a5f563b3695c7935adbb4531caf6c5d65aba1f8114202"
    $a5="576a277fb6154cbbd270f8de1a4c0bbda1a18732de7242c377216d459b15d26b440d97dc6ea16c26861a5f563b3695c7935adbb4531caf6c5d65aba1f8114202"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule blake2s_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "BLAKE2S"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="8fec74e6acbd030f34996103e61bb02459075b26bf5314c3664daca1ca829375"
    $a1="8fec74e6acbd030f34996103e61bb02459075b26bf5314c3664daca1ca829375"
    $a2="c71d04d1011f9bc585efc8a6a691c3dbe215327708a5ca0de4b8d4bc591da24b"
    $a3="c71d04d1011f9bc585efc8a6a691c3dbe215327708a5ca0de4b8d4bc591da24b"
    $a4="264861803adc0e9009b91730e72d831c5d150553952feee4c3cefcf1ff8fabbc"
    $a5="264861803adc0e9009b91730e72d831c5d150553952feee4c3cefcf1ff8fabbc"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_224_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "SHA3_224"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="457f6b86fb631acb87af20e0344cedbee5be2fdc9badd1d62c910a08"
    $a1="457f6b86fb631acb87af20e0344cedbee5be2fdc9badd1d62c910a08"
    $a2="f6eb28c154d3d8627fe393b04f5c0d3c25827fe6a7a72eb8ec7c4672"
    $a3="f6eb28c154d3d8627fe393b04f5c0d3c25827fe6a7a72eb8ec7c4672"
    $a4="5a74511105b388984bf453c7cf6cf0da18fdc2179ba250c8479546f1"
    $a5="5a74511105b388984bf453c7cf6cf0da18fdc2179ba250c8479546f1"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_256_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "SHA3_256"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="9896588693639f683fb7fd8122e993fff0b5a229f76787049530e53d7b566a59"
    $a1="9896588693639f683fb7fd8122e993fff0b5a229f76787049530e53d7b566a59"
    $a2="ee43538c914ae6eba6920eef5131535efa6da76ed7d914e637013d6cb47ad563"
    $a3="ee43538c914ae6eba6920eef5131535efa6da76ed7d914e637013d6cb47ad563"
    $a4="1e8f8d126fca81b63ed20e4a831e5a0453ace4c9042efea274329fd740bfb881"
    $a5="1e8f8d126fca81b63ed20e4a831e5a0453ace4c9042efea274329fd740bfb881"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_384_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "SHA3_384"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="526de9759ee8f505bb0012bd754f1c75a1948c972269153f2fedbf6c8238cf24f003d6cfbef8122da44bfa2d4bc541ca"
    $a1="526de9759ee8f505bb0012bd754f1c75a1948c972269153f2fedbf6c8238cf24f003d6cfbef8122da44bfa2d4bc541ca"
    $a2="6481bff91752a75350c7418779dcea20b705ffec22de4b3f5ea3926dd693f6128066a1aab34a0f636fbf2aa6135212d2"
    $a3="6481bff91752a75350c7418779dcea20b705ffec22de4b3f5ea3926dd693f6128066a1aab34a0f636fbf2aa6135212d2"
    $a4="91bc1fafc4c7e84200a31f696b046f3bed8d5c56667840f45f2ec38bf57094537656d12a7d75b31803086a799ddd7e75"
    $a5="91bc1fafc4c7e84200a31f696b046f3bed8d5c56667840f45f2ec38bf57094537656d12a7d75b31803086a799ddd7e75"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule sha3_512_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="a4e440f697e31b98cd6d02ae64080a53e460e5ec502bb61df8b1bdaa8f5ee4e21fc4c4a73f128298753b02cb9768d4a7622622e6a4157d9edfa608a6786932f4"
    $a1="a4e440f697e31b98cd6d02ae64080a53e460e5ec502bb61df8b1bdaa8f5ee4e21fc4c4a73f128298753b02cb9768d4a7622622e6a4157d9edfa608a6786932f4"
    $a2="bdb9e96e8b36ec882f4de8a77d2c023a4bd3df2ea0211533edd1ebca8b49c689c8a03c49f6f8f1e700d7c5b4038cecaf9c4ea296aec3584e5d064526edb002d8"
    $a3="bdb9e96e8b36ec882f4de8a77d2c023a4bd3df2ea0211533edd1ebca8b49c689c8a03c49f6f8f1e700d7c5b4038cecaf9c4ea296aec3584e5d064526edb002d8"
    $a4="57d4ab41183019c29a93b3b1dd6fe975070257eef551d95d081ff1e4749511bd4e93b21cca0a296a0ada5f457a500ac168db89edec3e13958f157518721a6772"
    $a5="57d4ab41183019c29a93b3b1dd6fe975070257eef551d95d081ff1e4749511bd4e93b21cca0a296a0ada5f457a500ac168db89edec3e13958f157518721a6772"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

rule base64_hashed_default_creds_pips_technology
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for pips_technology."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="d2xfdGVzdA=="
    $a1="d2xfdGVzdA=="
    $a2="dmVzc3RvcmU="
    $a3="dmVzc3RvcmU="
    $a4="ZnRwX2Jvb3Q="
    $a5="ZnRwX2Jvb3Q="
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5)
}

