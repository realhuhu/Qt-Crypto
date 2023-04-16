#include "constant.h"

namespace RSA {
    using namespace RSA_CONSTANT;

    qulonglong e; // 公钥
    qulonglong d; // 私钥

    // 求x^y % pq 的值，使用中国剩余定理加速
    qulonglong extModPow(qulonglong x, qulonglong y) {
        qulonglong m1, m2, M1, M2;
        m1 = M2 = p;
        m2 = M1 = q;
        auto M1R = modReverse(M1, m1);
        auto M2R = modReverse(M2, m2);
        auto b1 = modPow(x, y % (p - 1), m1);
        auto b2 = modPow(x, y % (q - 1), m2);
        return ((b1 * M1R * M1) % n + (b2 * M2R * M2) % n) % n;
    }

    // 根据私钥生成公钥
    QString initKey(const QString &key) {
        e = key.toULongLong(nullptr, 16);
        d = modReverse(e, RSA::m);
        if (!d) return "e没有逆元，请换一个私钥";
        return QString("公钥%1，私钥%2").arg(d).arg(e);
    }

    QString encrypt(const QString &plaintext) {
        qulonglong group;
        QString ciphertext;

        auto plaintextByteArray = plaintext.toUtf8().toHex();
        auto mod = plaintextByteArray.length() % 8;
        if (mod) plaintextByteArray = plaintextByteArray.prepend(8 - mod, '0');

        for (int i = 0; i <= (plaintextByteArray.length() - 1) / 8; i++) {
            // 按每8位拆分十六进制明文字符串
            group = plaintextByteArray.mid(8 * i, 8).toULongLong(nullptr, 16);

            // 运用公钥加密
            qulonglong res = extModPow(group, e);

            // 结果转为十六进制
            ciphertext += QString("%1").arg(QString::number(res, 16), 8, '0');
        }

        return ciphertext;
    }

    QString decrypt(const QString &ciphertext) {
        qulonglong group;
        QByteArray plaintext;

        for (int i = 0; i < ciphertext.length() / 8; i++) {
            // 按每8位拆分十六进制密文字符串
            group = ciphertext.midRef(8 * i, 8).toULongLong(nullptr, 16);

            // 运用私钥加密
            qulonglong res = extModPow(group, d);

            //结果转16进制字符串
            auto segment = QByteArray::number(res, 16);
            if (i && segment.length() != 8) segment.prepend("0", 8 - segment.length());

            plaintext += segment;
        }

        //16进制bytes转字符串
        return QByteArray::fromHex(plaintext);
    }
}