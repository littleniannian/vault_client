# 一个使用libcurl实现的对接hashicorp vault 的client
- init 解析external_kms_info，初始化client
- generate_key 生成一个rsa密钥
- update_key 密钥轮转，刷新一个新key
- get_key 获取密钥