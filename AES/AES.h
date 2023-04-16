#include "constant.h"

namespace AES {
    using namespace AES_CONSTANT;

    // 11个4×4密钥
    unsigned int K[44][4];

    QString initKey(QString &key) {
        // 不满32位十六进制数的，前端补0到32位
        if (key.length() != 32) key = QString("%1").arg(key, 32, QLatin1Char('0'));

        for (int i = 0; i < 4; i++) {
            // 依次取key的4个字节
            auto num_key = key.midRef(8 * i, 8).toULongLong(nullptr, 16);

            // 初始化密钥的前4×4部分
            for (int j = 3; j >= 0; j--, num_key /= 256)K[i][j] = num_key % 256;

            // 扩充密钥到44×4
            for (int j = 4; j < 43; j++) {
                if (j % 4) {
                    // w[i]=w[i−4]⊕w[i−1]
                    for (int k = 0; k < 4; k++) K[j][k] = K[j - 4][k] ^ K[j - 1][k];
                } else {
                    //w[i]=w[i−4]⊕T(w[i−1])
                    for (int k = 0; k < 4; k++) K[j][k] = K[j - 4][k] ^ S[K[j - 1][(k + 1) % 4]] ^ R[0][k];
                }
            }
        }
        return "密钥:" + key;
    }

    // 有限域乘法
    unsigned int mul(unsigned int a, unsigned int b) {
        unsigned int res = 0;
        while (a) {
            if (a % 2) res ^= b;
            b = b < 1 << 7 ? b << 1 : ((b << 1) & ((1 << 8) - 1)) ^ 0x1b;
            a /= 2;
        }
        return res;
    }

    // 有限域矩阵乘法
    void matrix_mul(unsigned int group[4][4], const unsigned int mat[4][4]) {
        unsigned int temp[4][4];
        memcpy(temp, group, 16 * sizeof(unsigned int));
        for (int i = 0; i < 16; i++) {
            group[i / 4][i % 4] = mul(mat[i / 4][0], temp[0][i % 4]) ^
                                  mul(mat[i / 4][1], temp[1][i % 4]) ^
                                  mul(mat[i / 4][2], temp[2][i % 4]) ^
                                  mul(mat[i / 4][3], temp[3][i % 4]);
        }
    }

    QString encrypt(const QString &plaintext) {
        unsigned int group[4][4], temp[4][4];
        QString ciphertext;

        auto plaintextByteArray = plaintext.toUtf8().toHex();
        auto mod = plaintextByteArray.length() % 32;
        if (mod) plaintextByteArray = plaintextByteArray.prepend(32 - mod, '0');//补齐到32位整数倍

        for (int i = 0; i <= (plaintextByteArray.length() - 1) / 32; i++) {
            //按照每32位拆分十六进制的明文
            for (int j = 0; j < 16; j++)
                group[j / 4][j % 4] = plaintextByteArray.mid(2 * j + 32 * i, 2).toUInt(nullptr, 16);


            for (int j = 0; j < 10; j++) {
                // 轮密钥加
                for (int k = 0; k < 16; k++) group[k / 4][k % 4] ^= K[4 * j + k / 4][k % 4];

                // 字节替代
                for (int k = 0; k < 16; k++) group[k / 4][k % 4] = S[group[k / 4][k % 4]];

                // 行位移
                memcpy(temp, group, 16 * sizeof(unsigned int));
                for (int k = 0; k < 16; k++) group[k / 4][k % 4] = temp[k / 4][(k / 4 + k % 4) % 4];

                if (j == 9) {
                    // 第10轮不需要列混淆，需要轮密钥加
                    for (int k = 0; k < 16; k++) group[k / 4][k % 4] ^= K[40 + k / 4][k % 4];
                } else {
                    // 列混淆
                    for (int k = 0; k < 16; k++) matrix_mul(group, ENC);
                }
            }

            //结果转16进制字符串
            for (int j = 0; j < 16; j++)
                ciphertext += QString("%1").arg(QString::number(group[j / 4][j % 4], 16), 2, '0');
        }

        return ciphertext;
    }

    QString decrypt(const QString &ciphertext) {
        unsigned int group[4][4], temp[4][4];
        QByteArray plaintext;

        for (int i = 0; i < ciphertext.length() / 32; i++) {
            //按照每32位拆分十六进制的明文
            for (int j = 0; j < 16; j++) group[j / 4][j % 4] = ciphertext.midRef(2 * j + 32 * i, 2).toUInt(nullptr, 16);

            for (int j = 0; j < 10; j++) {
                // 轮密钥加
                for (int k = 0; k < 16; k++) group[k / 4][k % 4] ^= K[40 - 4 * j + k / 4][k % 4];

                // 逆向行移位
                memcpy(temp, group, 16 * sizeof(unsigned int));
                for (int k = 0; k < 16; k++) group[k / 4][k % 4] = temp[k / 4][(4 - k / 4 + k % 4) % 4];

                // 逆向字节替代
                for (int k = 0; k < 16; k++) group[k / 4][k % 4] = SR[group[k / 4][k % 4]];

                if (j == 9) {
                    // 第10轮不需要逆向列混淆，需要轮密钥加
                    for (int k = 0; k < 16; k++) group[k / 4][k % 4] ^= K[k / 4][k % 4];
                } else {
                    // 逆向列混淆
                    for (int k = 0; k < 16; k++) matrix_mul(group, DEC);
                }
            }

            //结果转16进制bytes
            for (int j = 0; j < 16; j++) {
                auto segment = QByteArray::number(group[j / 4][j % 4], 16);
                if (plaintext.length() == 0 && segment == "0")continue;
                if (plaintext.length() && segment.length() != 2) segment.prepend("0", 1);
                plaintext += segment;
            }

        }

        //16进制bytes转字符串
        return QByteArray::fromHex(plaintext);
    }
}
