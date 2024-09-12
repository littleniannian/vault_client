//
// Created by Jarvis Yuen on 2024/9/11.
//

#ifndef VAULT_CLIENT_OB_ENCRYPT_KMS_H
#define VAULT_CLIENT_OB_ENCRYPT_KMS_H
#include <stdint.h>
#include <string>

using namespace std;

enum ObPostKmsMethod
{
    INVALID_METHOD = 0,
    GET_KEY,
    UPDATE_KEY,
    GENERATE_KEY,
    GET_PRIVATE_KEY,
    GET_PUBLIC_CERT,
};

class ObKmsClient {
public:
    ObKmsClient() {}
    ~ObKmsClient() {}
    virtual int init(const char *kms_info, int64_t kms_len) = 0;
    virtual int generate_key(const ObPostKmsMethod method, int64_t &key_version,
                             string &encrypted_key) = 0;
    virtual int update_key(int64_t &key_version, string &encrypted_key) = 0;
    virtual int get_key(int64_t key_version, const string &encrypted_key, string &key) = 0;
protected:
    static const int64_t OB_MAX_KMS_INFO_LEN = 5000;
};

class ObVaultClient: public ObKmsClient
{
public:
    enum KmsItem {
        KMS_HOST,
        TOKEN,
        PATH,
        KEY_NAME
    };
public:
    ObVaultClient() : ObKmsClient(), inited_(false),
                      kms_host_(""), token_(""), path_(""), key_name_("") {}
    virtual ~ObVaultClient() {};

public:
    virtual int init(const char *kms_info, int64_t kms_len) override;

    virtual int generate_key(const ObPostKmsMethod method, int64_t &key_version,
                             string &encrypted_key) override;

    virtual int update_key(int64_t &key_version, string &encrypted_key) override;

    virtual int get_key(int64_t key_version, const string &encrypted_key, string &key) override;
    const static char *kms_item[];

private:
    bool inited_;                         // initialization
    string kms_host_;           // kms请求地址
    string token_;              // kms请求token
    string path_;               // 请求路径
    string key_name_;            // 密钥名称
};


#endif //VAULT_CLIENT_OB_ENCRYPT_KMS_H
