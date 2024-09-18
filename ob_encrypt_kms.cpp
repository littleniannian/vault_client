#include "ob_encrypt_kms.h"
#include "ob_errno.h"
#include <curl/curl.h>
#include <json/json.h>
#include "ob_macro_utils.h"
#include <iostream>

using namespace oceanbase;
using namespace std;

static const int64_t BUF_SIZE = 2000;
static const int64_t RESPONSE_BUF_SIZE = BUF_SIZE * 2;
static const int64_t SIGN_BUF_SIZE = 345; // ceil(256 / 3) * 4 + 1

const char *ObVaultClient::kms_item[] = {
        "KMS_HOST",
        "TOKEN",
        "PATH",
        "KEY_NAME"
};

/**
 *
 * @param kms_info {
        "KMS_HOST": https://10.186.62.12:8200,
        "TOKEN": "aaaaaaaaaaa",
        "PATH": "test-transit",
        "KEY_NAME": "test_day_1"
    }
 * @param kms_len
 * @return
 */
int ObVaultClient::init(const char *kms_info, int64_t kms_len)
{
    int ret = OB_SUCCESS;
    Json::Reader reader;
    Json::Value kms_info_obj;
    // 将kms_info转换为对象
    // 校验kms_info的有效性
    // 从json对象中根据kms_item的枚举获取对应的值赋值给对应的成员变量
    if (reader.parse(kms_info, kms_info_obj)) {
        #define ENUM_TO_STR(val) #val
        kms_host_ = kms_info_obj[ENUM_TO_STR(KMS_HOST)].asString();
        token_ = kms_info_obj[ENUM_TO_STR(TOKEN)].asString();
        path_ = kms_info_obj[ENUM_TO_STR(PATH)].asString();
        key_name_ = kms_info_obj[ENUM_TO_STR(KEY_NAME)].asString();
        inited_ = true;
    }
    return ret;
}

size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

/**
 * 在hashicorp vault secret engine为transit的时候
 * 请求接口生成密钥
 * @param key_version
 * @return
 */
int ObVaultClient::generate_key(const ObPostKmsMethod method, int64_t &key_version,
                                string &encrypted_key) {
    int ret = OB_SUCCESS;
    UNUSED(encrypted_key);
    // 拼接URL
    string url = kms_host_ + "/v1/" + path_ + "/keys/" + key_name_;
    string post_body = R"({"convergent_encryption": true,"derived": true,"exportable": true,"allow_plaintext_backup": true,"type": "aes128-gcm96"})";
    CURL* curl;
    CURLcode res;
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    string response;
    if (curl) {
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        string token_header = "X-Vault-Token: " + token_;
        headers = curl_slist_append(headers, token_header.c_str());
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        // 下面两个参数用于忽略自签名SSL
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            cout << "Failed to send POST request: " << curl_easy_strerror(res) << endl;
        }
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    Json::Value root;
    Json::Reader reader;
    if (!reader.parse(response, root)) {
        std::cerr << "Failed to parse JSON string" << std::endl;
        ret = OB_ERROR;
        return ret;
    }
    key_version = root["data"]["latest_version"].asInt();
    return ret;
}

int ObVaultClient::update_key(int64_t &key_version, string &encrypted_key) {
    int ret = OB_SUCCESS;
    UNUSED(encrypted_key);
    string url = kms_host_ + "/v1/" + path_ + "/keys/" + key_name_ + "/rotate";
    CURL* curl;
    CURLcode res;
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    std::string response;
    if (curl) {
        string token_string = "X-Vault-Token: " + token_;
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, token_string.c_str());
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        // 下面两个参数用于忽略自签名SSL
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "Failed to send POST request: " << curl_easy_strerror(res) << std::endl;
        }
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    Json::Value root;
    Json::Reader reader;
    if (!reader.parse(response, root)) {
        std::cerr << "Failed to parse JSON string" << std::endl;
        ret = OB_ERROR;
        return ret;
    }
    key_version = root["data"]["latest_version"].asInt();
    return ret;
}

int ObVaultClient::get_key(int64_t key_version, const string &encrypted_key, string &key) {
    int ret = OB_SUCCESS;
    UNUSED(encrypted_key);
    CURL* curl;
    CURLcode res;
    string response;
    curl = curl_easy_init();
    if (curl) {
        string url = kms_host_ + "/v1/" + path_ + "/export/encryption-key/" + key_name_;
        struct curl_slist* headers = NULL;
        string token_header = "X-Vault-Token: " + token_;
        headers = curl_slist_append(headers, token_header.c_str());
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_POST, 0);
        // 下面两个参数用于忽略自签名SSL
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
        // 启用重定向跟随
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
        // 启用Verbose模式
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        } else {
            // 启用Verbose模式之后可以查看一些具体的请求信息
            char* final_url;
            curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &final_url);
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

            std::cout << "Final URL after redirection: " << final_url << std::endl;
            std::cout << "HTTP Response Code: " << http_code << std::endl;
        }
        curl_easy_cleanup(curl);
    }
    Json::Value root;
    Json::Reader reader;
    if (!reader.parse(response, root)) {
        std::cerr << "Failed to parse JSON " << std::endl;
        ret = OB_ERROR;
        return ret;
    }
    key = root["data"]["keys"][to_string(key_version)].asString();
    return ret;
}
