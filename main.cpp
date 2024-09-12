#include "ob_encrypt_kms.h"
#include <iostream>
#include <json/json.h>

using namespace std;

int main() {
    ObVaultClient client;
    char *kms_info = R"({"KMS_HOST": "https://10.186.62.12:8200","TOKEN": "hvs.E7hcsGsurVVXGXS2P5EsEZaO","PATH": "test-transit","KEY_NAME": "test_day_1"})";
    client.init(kms_info, strlen(kms_info));
    string encrypted_key;
    string key;
//    client.get_key(2, encrypted_key, key);
//    cout << "get vault key: " << key << endl;
    int64_t key_version;
    string encrypted_generate_key;
    client.generate_key(GENERATE_KEY, key_version, encrypted_key);
    cout << "generate vault key: " << key_version << endl;

    client.update_key(key_version, encrypted_key);
    cout << "生成一个新的key update vault key: " << key_version << endl;
    return 0;
}
