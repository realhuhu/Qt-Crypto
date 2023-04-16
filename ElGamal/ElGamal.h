#include <random>
#include "constant.h"

namespace ElGamal {
    using namespace ElGamal_CONSTANT;

    std::random_device seed;
    std::default_random_engine engine(seed());
    std::uniform_int_distribution<qulonglong> u(1, p - 2);

    qulonglong e, d;

    // 根据私钥生成公钥
    QString initKey(const QString &key) {
        d = key.toULongLong(nullptr, 16);
        e = modPow(alpha, d, p);
        return QString("公钥%1，私钥%2").arg(e).arg(d);
    }

    QString encrypt(const QString &plaintext) {
        qulonglong group;
        QString ciphertext1, ciphertext2;

        auto plaintextByteArray = plaintext.toUtf8().toHex();
        auto mod = plaintextByteArray.length() % 8;
        if (mod) plaintextByteArray = plaintextByteArray.prepend(8 - mod, '0');

        for (int i = 0; i <= (plaintextByteArray.length() - 1) / 8; i++) {
            // 按每8位拆分十六进制明文字符串
            group = plaintextByteArray.mid(8 * i, 8).toULongLong(nullptr, 16);

            // 生成随机数
            qulonglong k = u(engine);

            // 计算γ=α^k
            qulonglong gamma = modPow(alpha, k, p);

            // 计算δ=m·(α^a)^k
            qulonglong delta = group * modPow(e, k, p) % p;

            // 合并γ和δ
            ciphertext1 += QString("%1").arg(QString::number(gamma, 16), 8, '0');
            ciphertext2 += QString("%1").arg(QString::number(delta, 16), 8, '0');
        }

        // 用字符串形式输出γ和δ
        return ciphertext1 + "-" + ciphertext2;
    }

    QString decrypt(const QString &ciphertext) {
        qulonglong group;
        QByteArray plaintext;

        auto length = (ciphertext.length() - 1) / 2;
        for (int i = 0; i < length / 8; i++) {
            // 拆分出每组的γ和δ
            qulonglong gamma = ciphertext.midRef(8 * i, 8).toULongLong(nullptr, 16);
            qulonglong delta = ciphertext.midRef(length + 8 * i + 1, 8).toULongLong(nullptr, 16);

            // 还原出m
            group = delta * modReverse(modPow(gamma, d, p), p) % p;

            //结果转16进制字符串
            auto segment = QByteArray::number(group, 16);
            if (i && segment.length() != 8) segment.prepend("0", 8 - segment.length());

            plaintext += segment;
        }

        //16进制bytes转字符串
        return QByteArray::fromHex(plaintext);
    }
}