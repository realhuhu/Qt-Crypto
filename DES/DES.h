#include "constant.h"

namespace DES {
    using namespace DES_CONSTANT;

    bool K[16][48];

    //初始化十六个子密钥
    void initKey(const QString &key) {
        auto num_key = key.toULongLong(nullptr, 16);
        //转bool[64]
        bool bit_key[64];
        for (int i = 63; i >= 0; i--, num_key /= 2) bit_key[i] = num_key % 2;

        // PC1置换，得到出16组C和D
        int C[16][28], D[16][28];
        for (int i = 0; i < 56; i++) {
            int offset = 0;
            int from = PC1[i] - 1;
            for (int j = 0; j < 16; j++) {
                offset += LOOP[j];
                if (i < 28) {
                    C[j][(i - offset + 28) % 28] = bit_key[from];
                } else {
                    D[j][(i - offset + 28) % 28] = bit_key[from];
                }
            }
        }

        // PC2置换，利用16组C和D得到16个子密钥
        for (int i = 0; i < 16; i++) {
            for (int j = 0; j < 48; j++) {
                int from = PC2[j] - 1;
                if (from < 28) {
                    K[i][j] = C[i][from];
                } else {
                    K[i][j] = D[i][from - 28];
                }
            }
        }
    }

    //f运算
    void f(bool res[32], const bool r[32], const bool k[48]) {
        //32位的数据扩展成为48位
        bool expanded_res[48];
        for (int i = 0; i < 48; i++) expanded_res[i] = r[E[i] - 1] ^ k[i];

        //S盒替代，48位变成32位
        bool s_res[32];
        for (int i = 0; i < 8; i++) {
            int row = 2 * expanded_res[i * 6] + expanded_res[i * 6 + 5];
            int col = 8 * expanded_res[i * 6 + 1] +
                      4 * expanded_res[i * 6 + 2] +
                      2 * expanded_res[i * 6 + 3] +
                      expanded_res[i * 6 + 4];
            int s = S[i][row][col];
            for (int j = 3; j >= 0; j--, s /= 2) s_res[4 * i + j] = s % 2;
        }

        //进行P盒置换，32位输入，32位输出
        for (int i = 0; i < 32; i++)res[i] = s_res[P[i] - 1];
    }

    //将64bit的数字转化为bool[64]，根据IP表变换后拆成左半边的L1和右半边的R1
    void initial_permutation(qulonglong group, bool *L, bool *R) {
        bool bit_group[64];
        for (int i = 63; i >= 0; i--, group /= 2) bit_group[i] = group % 2;

        for (int i = 0; i < 64; i++) {
            if (i < 32) {
                L[i] = bit_group[IP[i] - 1];
            } else {
                R[i - 32] = bit_group[IP[i] - 1];
            }
        }
    }

    //利用十六个子密钥迭代L和R，得到L16和R16。通过reverse控制遍历子密钥的顺序
    void iteration(bool *L, bool *R, bool reverse) {
        bool L_temp[32], f_temp[32];
        for (int i = 0; i < 16; i++) {
            memcpy(L_temp, L, 32 * sizeof(bool));
            memcpy(L, R, 32 * sizeof(bool));
            f(f_temp, R, K[reverse ? 15 - i : i]);
            for (int k = 0; k < 32; k++)R[k] = f_temp[k] ^ L_temp[k];
        }

    }

    //拼接L16和R16。得到对应的64bit数
    qulonglong final_permutation(const bool *L, const bool *R) {
        qulonglong res = 0;
        for (int i: IPR) {
            res <<= 1;
            int index = i - 1;
            if (index < 32) {
                res += R[index];
            } else {
                res += L[index - 32];
            }
        }
        return res;
    }

    QString encrypt(const QString &plaintext) {
        qulonglong group;
        QString ciphertext;
        bool L[32], R[32];

        auto plaintextByteArray = plaintext.toUtf8().toHex();
        auto mod = plaintextByteArray.length() % 16;
        if (mod) plaintextByteArray = plaintextByteArray.prepend(16 - mod, '0');

        for (int i = 0; i <= (plaintextByteArray.length() - 1) / 16; i++) {
            //按照每16位拆分十六进制的明文
            group = plaintextByteArray.mid(16 * i, 16).toULongLong(nullptr, 16);

            //初始变换
            initial_permutation(group, L, R);

            //16次正向迭代
            iteration(L, R, false);

            //拼接L16和R16得到结果
            qulonglong res = final_permutation(L, R);

            //结果转16进制字符串
            ciphertext += QString("%1").arg(QString::number(res, 16), 16, '0');
        }

        return ciphertext;
    }

    QString decrypt(const QString &ciphertext) {
        qulonglong group;
        QByteArray plaintext;
        bool L[32], R[32];

        for (int i = 0; i < ciphertext.length() / 16; i++) {
            //按照每16位拆分十六进制的明文
            group = ciphertext.midRef(16 * i, 16).toULongLong(nullptr, 16);

            //初始变换
            initial_permutation(group, L, R);

            //16次反向迭代
            iteration(L, R, true);

            //拼接L16和R16得到结果
            qulonglong res = final_permutation(L, R);

            //结果转16进制bytes
            auto segment = QByteArray::number(res, 16);
            if (i && segment.length() != 16) segment.prepend("0", 16 - segment.length());

            plaintext += segment;
        }

        //16进制bytes转字符串
        return QByteArray::fromHex(plaintext);
    }
}
